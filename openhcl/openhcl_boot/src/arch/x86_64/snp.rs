// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SNP support for the bootshim.

use super::address_space::LocalMap;
use crate::PageAlign;
use crate::host_params::shim_params::ShimParams;
use core::arch::asm;
use core::hint::black_box;
use hvdef::HV_PAGE_SHIFT;
use hvdef::HV_PAGE_SIZE;
use hvdef::HvRegisterName;
use hvdef::HvRegisterValue;
use hvdef::HvX64RegisterName;
use hvdef::HvX64RegisterSevControl;
use hvdef::hypercall::HvInputVtl;
use hvdef::hypercall::HypercallOutput;
use memory_range::MemoryRange;
use minimal_rt::arch::fault;
use minimal_rt::arch::msr::read_msr;
use minimal_rt::arch::msr::write_msr;
use x86defs::X86X_AMD_MSR_GHCB;
use x86defs::snp::GhcbInfo;
use x86defs::snp::GhcbMsr;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;


#[derive(Debug)]
pub enum AcceptGpaStatus {
    Success,
    Retry,
}

#[expect(dead_code)] // Printed via Debug in the error case.
#[derive(Debug)]
pub enum AcceptGpaError {
    MemorySecurityViolation {
        error_code: u32,
        carry_flag: u32,
        page_number: u64,
        large_page: bool,
        validate: bool,
    },
    Unknown,
}

impl Ghcb {
    /// # Safety
    ///
    /// Regardless of the content of the GHCB page or MSR, this instruction should not be able
    /// to cause memory safety issues.
    fn sev_vmgexit() {
        // SAFETY: Using the `vmgexit` instruction forces an exit to the hypervisor but doesn't
        // directly change program state.
        unsafe {
            asm! {r#"
            rep vmmcall
            "#
            }
        }
    }

    pub fn change_page_visibility(range: MemoryRange, host_visible: bool) {
        // SAFETY: Always safe to read the GHCB MSR.
        let previous_value = unsafe { read_msr(X86X_AMD_MSR_GHCB) };
        for page_number in range.start_4k_gpn()..range.end_4k_gpn() {
            let extra_data = if host_visible {
                x86defs::snp::GHCB_DATA_PAGE_STATE_SHARED
            } else {
                x86defs::snp::GHCB_DATA_PAGE_STATE_PRIVATE
            };

            let val = (extra_data << 52) | (page_number << 12) | GhcbInfo::PAGE_STATE_CHANGE.0;

            // SAFETY: Writing known good value to the GHCB MSR.
            let val = unsafe {
                write_msr(X86X_AMD_MSR_GHCB, val);
                Self::sev_vmgexit();
                read_msr(X86X_AMD_MSR_GHCB)
            };

            // High 32 bits are status and should be 0 (HV_STATUS_SUCCESS), Low 32 bits should be
            // GHCB_INFO_PAGE_STATE_UPDATED. Assert if otherwise.

            assert!(
                val == GhcbInfo::PAGE_STATE_UPDATED.0,
                "GhcbInfo::PAGE_STATE_UPDATED returned msr value {val}"
            );
        }

        // SAFETY: Restoring previous GHCB value is safe.
        unsafe { write_msr(X86X_AMD_MSR_GHCB, previous_value) };
    }

    fn get_register(name: HvX64RegisterName) -> Result<HvRegisterValue, hvdef::HvError> {
        const HEADER_SIZE: usize = size_of::<hvdef::hypercall::GetSetVpRegisters>();

        // SAFETY: Always safe to read the GHCB MSR. The correctness of the bit pattern
        // is guaranteed by the hardware.
        let previous_ghcb = GhcbMsr::from_bits(unsafe { read_msr(X86X_AMD_MSR_GHCB) });

        let header = hvdef::hypercall::GetSetVpRegisters {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            vp_index: hvdef::HV_VP_INDEX_SELF,
            target_vtl: HvInputVtl::CURRENT_VTL,
            rsvd: [0; 3],
        };

        // SAFETY: The GHCB page comes from the measured BSP VMSA, must be set.
        let ghcb_page = unsafe {
            core::slice::from_raw_parts_mut(
                (previous_ghcb.pfn() << HV_PAGE_SHIFT) as *mut u8,
                HV_PAGE_SIZE as usize,
            )
        };

        // PANIC: Infallable, since the hypercall header is less than the size of a page
        header.write_to_prefix(ghcb_page).unwrap();
        // PANIC: Infallable, since the hypercall parameter (plus size of header above) is less than the size of a page
        name.write_to_prefix(&mut ghcb_page[HEADER_SIZE..]).unwrap();

        let control = hvdef::hypercall::Control::new()
            .with_code(hvdef::HypercallCode::HvCallGetVpRegisters.0)
            .with_rep_count(1)
            .with_fast(false);
        let ghcb = GhcbMsr::new()
            .with_pfn(previous_ghcb.pfn())
            .with_info(GhcbInfo::SPECIAL_HYPERCALL.0)
            .with_extra_data(control.into_bits());

        // SAFETY: Writing known good value to the GHCB MSR, following the GHCB protocol.
        let ghcb: GhcbMsr = unsafe {
            core::mem::transmute({
                write_msr(X86X_AMD_MSR_GHCB, ghcb.into_bits());
                Self::sev_vmgexit();
                read_msr(X86X_AMD_MSR_GHCB)
            })
        };

        assert!(ghcb.info() == GhcbInfo::HYPERCALL_OUTPUT.0);

        let output = HypercallOutput::from_bits(((ghcb.into_bits() >> 16) & 0xFFF) as u64);
        output.result()?;

        let val = HvRegisterValue::read_from_prefix(&ghcb_page).unwrap().0;

        // SAFETY: Restoring previous GHCB value is safe.
        unsafe { write_msr(X86X_AMD_MSR_GHCB, previous_ghcb.into_bits()) };

        Ok(val)
    }

    fn set_register(name: HvRegisterName, value: HvRegisterValue) -> Result<(), hvdef::HvError> {
        const HEADER_SIZE: usize = size_of::<hvdef::hypercall::GetSetVpRegisters>();

        // SAFETY: Always safe to read the GHCB MSR. The correctness of the bit pattern
        // is guaranteed by the hardware.
        let previous_ghcb = GhcbMsr::from_bits(unsafe { read_msr(X86X_AMD_MSR_GHCB) });

        let header = hvdef::hypercall::GetSetVpRegisters {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            vp_index: hvdef::HV_VP_INDEX_SELF,
            target_vtl: HvInputVtl::CURRENT_VTL,
            rsvd: [0; 3],
        };
        let reg = hvdef::hypercall::HvRegisterAssoc {
            name,
            pad: Default::default(),
            value,
        };

        // SAFETY: The GHCB page comes from the measured BSP VMSA, must be set.
        let ghcb_page = unsafe {
            core::slice::from_raw_parts_mut(
                (previous_ghcb.pfn() << HV_PAGE_SHIFT) as *mut u8,
                HV_PAGE_SIZE as usize,
            )
        };

        // PANIC: Infallable, since the hypercall header is less than the size of a page
        header.write_to_prefix(ghcb_page).unwrap();
        // PANIC: Infallable, since the hypercall parameter (plus size of header above) is less than the size of a page
        reg.write_to_prefix(&mut ghcb_page[HEADER_SIZE..]).unwrap();

        let control = hvdef::hypercall::Control::new()
            .with_code(hvdef::HypercallCode::HvCallGetVpRegisters.0)
            .with_rep_count(1)
            .with_fast(false);
        let ghcb = GhcbMsr::new()
            .with_pfn(previous_ghcb.pfn())
            .with_info(GhcbInfo::SPECIAL_HYPERCALL.0)
            .with_extra_data(control.into_bits());

        // SAFETY: Writing known good value to the GHCB MSR, following the GHCB protocol.
        let ghcb: GhcbMsr = unsafe {
            core::mem::transmute({
                write_msr(X86X_AMD_MSR_GHCB, ghcb.into_bits());
                Self::sev_vmgexit();
                read_msr(X86X_AMD_MSR_GHCB)
            })
        };

        assert!(ghcb.info() == GhcbInfo::HYPERCALL_OUTPUT.0);

        // SAFETY: Restoring previous GHCB value is safe.
        unsafe { write_msr(X86X_AMD_MSR_GHCB, previous_ghcb.into_bits()) };

        let output = HypercallOutput::from_bits(((ghcb.into_bits() >> 16) & 0xFFF) as u64);
        output.result()
    }
}

/// Wrapper around the pvalidate assembly instruction.
fn pvalidate(
    page_number: u64,
    va: u64,
    large_page: bool,
    validate: bool,
) -> Result<AcceptGpaStatus, AcceptGpaError> {
    if large_page {
        assert!(va % x86defs::X64_LARGE_PAGE_SIZE == 0);
    } else {
        assert!(va % hvdef::HV_PAGE_SIZE == 0)
    }

    let validate_page = validate as u32;
    let page_size = large_page as u32;
    let mut error_code: u32;
    let mut carry_flag: u32 = 0;

    // SAFETY: Issuing pvalidate according to specification.
    unsafe {
        asm!(r#"
        pvalidate
        jnc 2f
        inc {carry_flag:e}
        2:
        "#,
        in("rax") va,
        in("ecx") page_size,
        in("edx") validate_page,
        lateout("eax") error_code,
        carry_flag = inout(reg) carry_flag);
    }

    const SEV_SUCCESS: u32 = 0;
    const SEV_FAIL_SIZEMISMATCH: u32 = 6;

    match (error_code, carry_flag) {
        (SEV_SUCCESS, 0) => Ok(AcceptGpaStatus::Success),
        (SEV_FAIL_SIZEMISMATCH, _) => Ok(AcceptGpaStatus::Retry),
        _ => Err(AcceptGpaError::MemorySecurityViolation {
            error_code,
            carry_flag,
            page_number,
            large_page,
            validate,
        }),
    }
}

/// Accepts or unaccepts a specific gpa range. On SNP systems, this corresponds to issuing a
/// pvalidate over the GPA range with the desired value of the validate bit.
pub fn set_page_acceptance(
    local_map: &mut LocalMap<'_>,
    range: MemoryRange,
    validate: bool,
) -> Result<(), AcceptGpaError> {
    let pages_per_large_page = x86defs::X64_LARGE_PAGE_SIZE / hvdef::HV_PAGE_SIZE;
    let mut page_count = range.page_count_4k();
    let mut page_base = range.start_4k_gpn();

    while page_count != 0 {
        // Attempt to validate a large page.
        // Even when pvalidating a large page, the processor only does a 1 byte read. As a result
        // mapping a single page is sufficient.
        let mapping = local_map.map_pages(
            MemoryRange::from_4k_gpn_range(page_base..page_base + 1),
            true,
        );
        if page_base % pages_per_large_page == 0 && page_count >= pages_per_large_page {
            let res = pvalidate(page_base, mapping.data.as_ptr() as u64, true, validate)?;
            match res {
                AcceptGpaStatus::Success => {
                    page_count -= pages_per_large_page;
                    page_base += pages_per_large_page;
                    continue;
                }
                AcceptGpaStatus::Retry => (),
            }
        }

        // Attempt to validate a regular sized page.
        let res = pvalidate(page_base, mapping.data.as_ptr() as u64, false, validate)?;
        match res {
            AcceptGpaStatus::Success => {
                page_count -= 1;
                page_base += 1;
            }
            AcceptGpaStatus::Retry => {
                // Cannot retry on a regular sized page.
                return Err(AcceptGpaError::Unknown);
            }
        }
    }

    Ok(())
}

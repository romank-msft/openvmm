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

#[repr(C, packed)]
struct GhcbSaveArea {
    reserved_0x0: [u8; 203],
    cpl: u8,
    reserved_0xcc: [u8; 116],
    xss: u64,
    reserved_0x148: [u8; 24],
    dr7: u64,
    reserved_0x168: [u8; 16],
    rip: u64,
    reserved_0x180: [u8; 88],
    rsp: u64,
    reserved_0x1e0: [u8; 24],
    rax: u64,
    reserved_0x200: [u8; 264],
    rcx: u64,
    rdx: u64,
    rbx: u64,
    reserved_0x320: [u8; 8],
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    reserved_0x380: [u8; 16],
    sw_exit_code: u64,
    sw_exit_info_1: u64,
    sw_exit_info_2: u64,
    sw_scratch: u64,
    reserved_0x3b0: [u8; 56],
    xcr0: u64,
    valid_bitmap: [u8; 16],
    x87_state_gpa: u64,
}

#[repr(C, packed)]
pub struct Ghcb {
    save: GhcbSaveArea,
    reserved_save: [u8; 2048 - size_of::<GhcbSaveArea>()],
    shared_buffer: [u8; 2032],
    reserved_0xff0: [u8; 10],
    protocol_version: u16,
    ghcb_usage: u32,
}

const _: () = assert!(size_of::<Ghcb>() == HV_PAGE_SIZE as usize);

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
        assert!(va % HV_PAGE_SIZE == 0)
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
    let pages_per_large_page = x86defs::X64_LARGE_PAGE_SIZE / HV_PAGE_SIZE;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum UpdateFeaturesStep {
    NotStarted = 0,
    TemporaryVmsa,
    BootVmsa,
}

struct UpdateFeaturesState {
    step: UpdateFeaturesStep,
    temp_vmsa: u64,
    boot_vmsa: u64,
}

/// Upgrade the VMSA features to the desired ones.
///
/// The BSP boots off of the most hardware-compatible VMSA. The function:
///     1. Switches to a temporary VMSA, which is the copy of the boot VMSA,
///     2. Updates the features of the boot VMSA,
///     3. Switches back to the boot VMSA,
///     4. Marks the temporary VMSA as inactive.
///
/// The sequence allows a transparent for the other code upgrade at the cost of the 4KiB.
/// The shared part of the GHCB is used for persistence between switching the VMSA pages.
/// The assumption is that the shared part of the GHCB page has is zeroed out in the IGVM file.
///
/// Due to running in the identity mapping, the GVAs and GPAs are the same.
///
/// The callers must ensure not to run any code touching GHCB prior to this function due to
/// which it is marked unsafe -- the compiler cannot prove that the GHCB is not used through
/// the pressent form of the code.
///
/// Data manipulation by a malious hypervisor with the GHCB content won't break the confidentiality,
/// might cause DoS o performance issues if the feature upgrade is prevented.
pub unsafe fn update_vmsa_features(p: &ShimParams) {
    if !p.auto_enable_secure_avic {
        return;
    }

    // TODO: from the SEV status or VMSA see if secure AVIC is alreaady enabled.
    // proceeed if not.

    // SAFETY: The GHCB MSR is always safe to read.
    let ghcb = GhcbMsr::from_bits(unsafe { read_msr(X86X_AMD_MSR_GHCB) });
    let ghcb = unsafe {
        ((ghcb.pfn() << HV_PAGE_SHIFT) as *mut PageAlign<Ghcb>)
            .as_mut()
            .expect("GHCB is not NULL")
    };

    // SAFETY: INitially zeroed out which is a valid state, later controlled by this function.
    // The callers must ensure not to run any code touching GHCB prior to this function due to
    // which it is marked unsafe -- the compiler cannot prove that the GHCB is not used through
    // the pressent form of the code.
    let upgrade_state =
        unsafe { (ghcb.0.shared_buffer.as_mut_ptr() as *mut UpdateFeaturesState).as_mut() }
            .expect("the GHCB shared buffer is not NULL");

    match upgrade_state.step {
        UpdateFeaturesStep::NotStarted => {
            // TODO: See if the feature upgrade is required.

            let sev_control =
                Ghcb::get_register(HvX64RegisterName::SevControl).expect("get SEV control");
            let sev_control =
                HvX64RegisterSevControl::read_from_bytes(&sev_control.0.as_ne_bytes())
                    .expect("read SEV control into the structure");

            // SAFETY: The VMSA is a 4KiB page, and the SEV control register points to it.
            // If the hypervsisor returns an invalid value, the guest confidentiality won't be compromised,
            // DoS is not a concern.
            let boot_vmsa = sev_control.vmsa_gpa_page_number();

            // A temporary scratch page is allocated in the IGVM file right after the
            // shim parameters page.
            //
            // Cannot use the static data without nasty hacks as the BSS is wiped out when entering
            // the shim.
            let temp_vmsa = p.scratch_page_addr;

            upgrade_state.temp_vmsa = temp_vmsa;
            upgrade_state.boot_vmsa = boot_vmsa;
            upgrade_state.step = UpdateFeaturesStep::TemporaryVmsa;

            // TODO: copy the VMSA page to the temporary page.
            // TODO: RMP adjust the temp VMSA page to mark it as a VMSA page.

            let temp_sev_control = sev_control
                .with_vmsa_gpa_page_number(upgrade_state.temp_vmsa as u64 >> HV_PAGE_SHIFT);

            // Switch to the temporary VMSA to reenter the shim.
            Ghcb::set_register(
                HvX64RegisterName::SevControl.into(),
                HvRegisterValue::from(temp_sev_control.into_bits()),
            )
            .expect("must be ablle to get SEV control");

            // Cannot get here
            black_box(if upgrade_state.step != UpdateFeaturesStep::TemporaryVmsa {
                fault();
            });
        }
        UpdateFeaturesStep::TemporaryVmsa => todo!(),
        UpdateFeaturesStep::BootVmsa => todo!(),
    }
}

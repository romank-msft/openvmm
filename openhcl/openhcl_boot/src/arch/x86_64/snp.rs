// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SNP support for the bootshim.

use super::address_space::LocalMap;
use core::arch::asm;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use hvdef::HV_PAGE_SHIFT;
use hvdef::HV_PAGE_SIZE;
use hvdef::HvRegisterName;
use hvdef::HvRegisterValue;
use hvdef::HvX64RegisterName;
use hvdef::hypercall::HvInputVtl;
use hvdef::hypercall::HypercallOutput;
use memory_range::MemoryRange;
use minimal_rt::arch::msr::read_msr;
use minimal_rt::arch::msr::write_msr;
use x86defs::X86X_AMD_MSR_GHCB;
use x86defs::snp::GhcbInfo;
use x86defs::snp::GhcbMsr;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, IntoBytes, FromBytes)]
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
#[derive(Debug, Copy, Clone, IntoBytes, FromBytes)]
pub struct GhcbPage {
    save: GhcbSaveArea,
    reserved_save: [u8; 2048 - size_of::<GhcbSaveArea>()],
    shared_buffer: [u8; 2032],
    reserved_0xff0: [u8; 10],
    protocol_version: u16,
    ghcb_usage: u32,
}

const _: () = assert!(size_of::<GhcbPage>() == HV_PAGE_SIZE as usize);

static GHCB_PAGE: AtomicPtr<GhcbPage> = AtomicPtr::new(core::ptr::null_mut() as *mut GhcbPage);
static GHCB_PREVIOUS: AtomicU64 = AtomicU64::new(0);

pub struct Ghcb;

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

struct GhcbCall {
    extra_data: u64,
    page_number: u64,
    info: GhcbInfo,
}

#[must_use]
fn map_ghcb_page(page_number: u64) -> *mut GhcbPage {
    // Flipping the C-bit made the contents of the GHCB page scrambled,
    // zero it out.
    // SAFETY: The GHCB page is statically allocated and initialized.
    // unsafe {
    //     ghcb_ptr.as_mut().unwrap().as_mut_bytes().fill(0);
    // }

    // TODO: MAp and set the C-bit
    (page_number << HV_PAGE_SHIFT) as *mut GhcbPage
}

/// Unmap the GHCB page.
fn unmap_ghcb_page(ghcb_ptr: *mut GhcbPage) {}

impl Ghcb {
    pub fn initialize(page_number: u64) {
        assert!(page_number != u64::MAX && page_number != 0);

        // SAFETY: Always safe to read the GHCB MSR, no concurrency issues.
        GHCB_PREVIOUS.store(unsafe { read_msr(X86X_AMD_MSR_GHCB) }, Ordering::Release);

        let ghcb_ptr = map_ghcb_page(page_number);
        assert!(!ghcb_ptr.is_null(), "GHCB page is not mapped");

        let resp = Self::ghcb_call(GhcbCall {
            extra_data: 0,
            page_number,
            info: GhcbInfo::REGISTER_REQUEST,
        });

        assert!(
            resp.info() == GhcbInfo::REGISTER_RESPONSE
                && resp.extra_data() == 0
                && resp.pfn() == page_number,
            "GhcbInfo::REGISTER_RESPONSE returned msr value {resp:x?}"
        );

        GHCB_PAGE.store(ghcb_ptr, Ordering::Release);
    }

    pub fn uninitialize() {
        // SAFETY: Always safe to write the GHCB MSR, no concurrency issues.
        unsafe { write_msr(X86X_AMD_MSR_GHCB, GHCB_PREVIOUS.load(Ordering::Acquire)) };
        unmap_ghcb_page(GHCB_PAGE.load(Ordering::Acquire));
        // TODO: clear the globals
    }

    fn ghcb() -> &'static GhcbPage {
        // SAFETY: The GHCB page is statically allocated and initialized.
        unsafe {
            GHCB_PAGE
                .load(Ordering::Acquire)
                .as_ref()
                .expect("GHCB page is set")
        }
    }

    fn ghcb_mut() -> &'static mut GhcbPage {
        // SAFETY: The GHCB page is statically allocated and initialized.
        unsafe {
            GHCB_PAGE
                .load(Ordering::Acquire)
                .as_mut()
                .expect("GHCB page is set")
        }
    }

    fn ghcb_address() -> u64 {
        let addr = GHCB_PAGE.load(Ordering::Acquire) as u64;
        assert!(addr != 0, "GHCB page is not set");
        addr
    }

    /// Perform the GHCB call
    fn ghcb_call(call_data: GhcbCall) -> GhcbMsr {
        let GhcbCall {
            info,
            extra_data,
            page_number,
        } = call_data;
        let ghcb_control = GhcbMsr::new()
            .with_pfn(page_number)
            .with_info(info)
            .with_extra_data(extra_data);

        GhcbMsr::from_bits(
            // SAFETY: Writing and reding known good value to/from the GHCB MSR, following the GHCB protocol.
            // SAFETY: Using the `vmgexit` instruction forces an exit to the hypervisor but doesn't
            // directly change program state.
            unsafe {
                write_msr(X86X_AMD_MSR_GHCB, ghcb_control.into_bits());
                asm!("rep vmmcall", options(nomem, nostack));
                read_msr(X86X_AMD_MSR_GHCB)
            },
        )
    }

    pub fn change_page_visibility(range: MemoryRange, host_visible: bool) {
        for page_number in range.start_4k_gpn()..range.end_4k_gpn() {
            let extra_data = if host_visible {
                x86defs::snp::GHCB_DATA_PAGE_STATE_SHARED
            } else {
                x86defs::snp::GHCB_DATA_PAGE_STATE_PRIVATE
            };

            let resp = Self::ghcb_call(GhcbCall {
                info: GhcbInfo::PAGE_STATE_CHANGE,
                extra_data,
                page_number,
            });

            // High 32 bits are status and should be 0 (HV_STATUS_SUCCESS), Low 32 bits should be
            // GHCB_INFO_PAGE_STATE_UPDATED. Assert if otherwise.

            assert!(
                resp.into_bits() == GhcbInfo::PAGE_STATE_UPDATED.0,
                "GhcbInfo::PAGE_STATE_UPDATED returned msr value {resp:x?}"
            );
        }
    }

    fn get_register(&self, name: HvX64RegisterName) -> Result<HvRegisterValue, hvdef::HvError> {
        const HEADER_SIZE: usize = size_of::<hvdef::hypercall::GetSetVpRegisters>();

        let header = hvdef::hypercall::GetSetVpRegisters {
            partition_id: hvdef::HV_PARTITION_ID_SELF,
            vp_index: hvdef::HV_VP_INDEX_SELF,
            target_vtl: HvInputVtl::CURRENT_VTL,
            rsvd: [0; 3],
        };

        let ghcb_page = Self::ghcb_mut().as_mut_bytes();

        // PANIC: Infallable, since the hypercall header is less than the size of a page
        header.write_to_prefix(ghcb_page).unwrap();
        // PANIC: Infallable, since the hypercall parameter (plus size of header above) is less than the size of a page
        name.write_to_prefix(&mut ghcb_page[HEADER_SIZE..]).unwrap();

        let control = hvdef::hypercall::Control::new()
            .with_code(hvdef::HypercallCode::HvCallGetVpRegisters.0)
            .with_rep_count(1)
            .with_fast(false);

        let resp = Self::ghcb_call(GhcbCall {
            info: GhcbInfo::SPECIAL_HYPERCALL,
            extra_data: control.into_bits(),
            page_number: Self::ghcb_address(),
        });

        assert!(resp.info().0 == GhcbInfo::HYPERCALL_OUTPUT.0);
        HypercallOutput::from_bits(((resp.into_bits() >> 16) & 0xFFF) as u64).result()?;

        Ok(HvRegisterValue::read_from_prefix(&ghcb_page).unwrap().0)
    }

    fn set_register(name: HvRegisterName, value: HvRegisterValue) -> Result<(), hvdef::HvError> {
        const HEADER_SIZE: usize = size_of::<hvdef::hypercall::GetSetVpRegisters>();

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

        let ghcb_page = Self::ghcb_mut().as_mut_bytes();

        // PANIC: Infallable, since the hypercall header is less than the size of a page
        header.write_to_prefix(ghcb_page).unwrap();
        // PANIC: Infallable, since the hypercall parameter (plus size of header above) is less than the size of a page
        reg.write_to_prefix(&mut ghcb_page[HEADER_SIZE..]).unwrap();

        let control = hvdef::hypercall::Control::new()
            .with_code(hvdef::HypercallCode::HvCallGetVpRegisters.0)
            .with_rep_count(1)
            .with_fast(false);

        let resp = Self::ghcb_call(GhcbCall {
            info: GhcbInfo::SPECIAL_HYPERCALL,
            extra_data: control.into_bits(),
            page_number: Self::ghcb_address(),
        });

        assert!(resp.info() == GhcbInfo::HYPERCALL_OUTPUT);

        HypercallOutput::from_bits(((resp.into_bits() >> 16) & 0xFFF) as u64).result()
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

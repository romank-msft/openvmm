// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SNP support for the bootshim.

use super::address_space::LocalMap;
use super::address_space::PAGE_TABLE_ENTRY_COUNT;
use super::address_space::X64_PAGE_SHIFT;
use super::address_space::X64_PTE_ACCESSED;
use super::address_space::X64_PTE_PRESENT;
use super::address_space::X64_PTE_READ_WRITE;
use crate::arch::x86_64::address_space::X64_PTE_CONFIDENTIAL;
use crate::single_threaded::SingleThreaded;
use bitfield_struct::bitfield;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use core::sync::atomic::compiler_fence;
use core::sync::atomic::fence;
use hvdef::HV_PAGE_SHIFT;
use hvdef::HV_PAGE_SIZE;
use memory_range::MemoryRange;
use minimal_rt::arch::msr::read_msr;
use minimal_rt::arch::msr::write_msr;
use x86defs::X64_PAGE_SIZE;
use x86defs::X86X_AMD_MSR_GHCB;
use x86defs::snp::GhcbInfo;
use x86defs::snp::GhcbMsr;
use x86defs::snp::GhcbPage;
use x86defs::snp::GhcbProtocolVersion;
use x86defs::snp::GhcbSaveArea;
use x86defs::snp::GhcbUsage;
use x86defs::snp::SevExitCode;
use x86defs::snp::SevIoAccessInfo;
use zerocopy::IntoBytes;

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

// The memory mapping bits likely don't belong to this module, but
// no centralized facility seems to exist for them yet.

/// 4-level virtual address. The number of bits used in the VA
/// ought to be requested through CPUID. Here it is "hardcoded"
/// to 48 bits, which is the most common case.
#[bitfield(u64)]
struct VirtAddr4Level {
    /// Offset inside the page.
    #[bits(12)]
    offset: usize,
    /// PT index.
    #[bits(9)]
    pt_index: usize,
    /// PD index.
    #[bits(9)]
    pd_index: usize,
    /// PDP index.
    #[bits(9)]
    pdp_index: usize,
    /// PML4 index.
    #[bits(9)]
    pml4_index: usize,
    /// Reserved bits.
    #[bits(16)]
    reserved: usize,
}

impl VirtAddr4Level {
    const fn canonicalize(&self) -> VirtAddr4Level {
        // If PML4 is greater than 255, make it upper-half canonical
        // by sign extending the PML4 index.
        Self::from_bits((self.into_bits().wrapping_shl(16) as i64).wrapping_shr(16) as u64)
    }

    const fn as_mut_ptr<T>(&self) -> *mut T {
        self.canonicalize().into_bits() as *mut T
    }
}

// Would be great to allocate this pages dynamically as otherwise they go
// into the IGVM file and require measurement through the PSP.

/// PDP table to map the GHCB
static PDP_TABLE: SingleThreaded<UnsafeCell<[u64; PAGE_TABLE_ENTRY_COUNT]>> =
    SingleThreaded(UnsafeCell::new([0; PAGE_TABLE_ENTRY_COUNT]));

/// PD table to map the GHCB
static PD_TABLE: SingleThreaded<UnsafeCell<[u64; PAGE_TABLE_ENTRY_COUNT]>> =
    SingleThreaded(UnsafeCell::new([0; PAGE_TABLE_ENTRY_COUNT]));

/// Page table to map the GHCB
static PAGE_TABLE: SingleThreaded<UnsafeCell<[u64; PAGE_TABLE_ENTRY_COUNT]>> =
    SingleThreaded(UnsafeCell::new([0; PAGE_TABLE_ENTRY_COUNT]));

/// Page table to map the GHCB
static GHCB: SingleThreaded<UnsafeCell<[u8; size_of::<GhcbPage>()]>> =
    SingleThreaded(UnsafeCell::new([0; size_of::<GhcbPage>()]));

const PML4_INDEX: usize = 0x1d0; // upper half mapping
const PDP_INDEX: usize = 0;
const PD_INDEX: usize = 0;
const PT_INDEX: usize = 0;
const GHCB_ADDR: VirtAddr4Level = VirtAddr4Level::new()
    .with_pt_index(PT_INDEX)
    .with_pd_index(PD_INDEX)
    .with_pdp_index(PDP_INDEX)
    .with_pml4_index(PML4_INDEX)
    .canonicalize();

fn get_cr3() -> u64 {
    let mut cr3: u64;

    // SAFETY: No access to the memory.
    unsafe {
        asm!("mov {0}, cr3", out(reg) cr3, options(nostack));
    }
    cr3
}

fn cache_lines_flush_page(addr: u64) {
    const FLUSH_SIZE: u64 = 64; // NOTE: hardcoded cache line size.
    let start = addr & !(X64_PAGE_SIZE - 1);
    let end = start + X64_PAGE_SIZE;

    // Make sure there are no pending writes on the cache lines.
    fence(Ordering::SeqCst);

    for addr in (start..end).step_by(FLUSH_SIZE as usize) {
        // SAFETY: No concurrency issues.
        unsafe {
            asm!("clflush [{0}]", in(reg) addr, options(nostack));
        }
    }
}

fn flush_tlb() {
    fence(Ordering::SeqCst);
    // NOTE: no flush for the global pages.
    // SAFETY: No concurrency issues.
    unsafe {
        asm!("mov cr3, {0}", in(reg) get_cr3(), options(nostack));
    }
    compiler_fence(Ordering::SeqCst);
}

fn page_table(pfn: u64) -> &'static mut [u64] {
    // SAFETY: The next page address must be set, identical mapping.
    unsafe {
        core::slice::from_raw_parts_mut((pfn << HV_PAGE_SHIFT) as *mut u64, PAGE_TABLE_ENTRY_COUNT)
    }
}

fn pte_for_pfn(pfn: u64, confidential: bool) -> u64 {
    let common = X64_PTE_PRESENT | X64_PTE_ACCESSED | X64_PTE_READ_WRITE | (pfn << X64_PAGE_SHIFT);
    if confidential {
        common | X64_PTE_CONFIDENTIAL
    } else {
        common
    }
}

fn map_ghcb_page() {
    let page_root = get_cr3() & !(HV_PAGE_SIZE - 1);
    let pml4table = page_table(page_root >> HV_PAGE_SHIFT);
    assert!(pml4table[PML4_INDEX] & X64_PTE_PRESENT == 0);

    // Running in identical mapping.
    let pdp_table_pfn = (PDP_TABLE.get() as u64) >> X64_PAGE_SHIFT;
    let pd_table_pfn = (PD_TABLE.get() as u64) >> X64_PAGE_SHIFT;
    let page_table_pfn = (PAGE_TABLE.get() as u64) >> X64_PAGE_SHIFT;
    let page_number = (GHCB.get() as u64) >> X64_PAGE_SHIFT;

    let pdp_table = page_table(pdp_table_pfn);
    let pd_table = page_table(pd_table_pfn);
    let page_table = page_table(page_table_pfn);

    pml4table[PML4_INDEX] = pte_for_pfn(pdp_table_pfn, true);
    pdp_table[PDP_INDEX] = pte_for_pfn(pd_table_pfn, true);
    pd_table[PD_INDEX] = pte_for_pfn(page_table_pfn, true);
    page_table[PT_INDEX] = pte_for_pfn(page_number, true);

    flush_tlb();
    // Evict the page from the cache before changing the encrypted state.
    cache_lines_flush_page(GHCB_ADDR.into_bits());

    let ghcb_ptr: *mut GhcbPage = GHCB_ADDR.as_mut_ptr();

    // Unaccept the page, invalidates page state.
    pvalidate(page_number, ghcb_ptr as u64, false, false).expect("memory unaccept");
    // Issue VMGS exit to request the hypervisor to update the page state to host visible in RMP.
    let resp = Ghcb::ghcb_call(GhcbCall {
        info: GhcbInfo::PAGE_STATE_CHANGE,
        extra_data: x86defs::snp::GHCB_DATA_PAGE_STATE_SHARED,
        page_number,
    });
    assert!(resp.into_bits() == GhcbInfo::PAGE_STATE_UPDATED.0);

    // Map the page as non-confidential by updating the PTE.
    page_table[PT_INDEX] = pte_for_pfn(page_number, false);
    flush_tlb();
    // Evict the page from the cache before changing the encrypted state.
    cache_lines_flush_page(GHCB_ADDR.into_bits());

    // Flipping the C-bit makes the contents of the GHCB page scrambled,
    // zero it out.
    // SAFETY: the apge is statically-allocated, single-threaded access.
    unsafe {
        ghcb_ptr
            .as_mut()
            .expect("GHCB page is set")
            .as_mut_bytes()
            .fill(0);
    }

    GHCB_PAGE.store(ghcb_ptr, Ordering::Release);
}

/// Unmap the GHCB page.
fn unmap_ghcb_page() {
    GHCB_PAGE.store(core::ptr::null_mut(), Ordering::Release);

    let ghcb_ptr: *mut GhcbPage = GHCB_ADDR.as_mut_ptr();

    // Evict the page from the cache before changing the encrypted state.
    cache_lines_flush_page(GHCB_ADDR.into_bits());

    // Update the page table entry to make it confidential.
    // Running in identical mapping.
    let page_table_pfn = (PAGE_TABLE.get() as u64) >> X64_PAGE_SHIFT;
    let page_table = page_table(page_table_pfn);
    let page_number = (GHCB.get() as u64) >> X64_PAGE_SHIFT;

    page_table[PT_INDEX] |= X64_PTE_CONFIDENTIAL;
    flush_tlb();

    // Issue VMGS exit to request the hypervisor to update the page state to private in RMP.
    let resp = Ghcb::ghcb_call(GhcbCall {
        info: GhcbInfo::PAGE_STATE_CHANGE,
        extra_data: x86defs::snp::GHCB_DATA_PAGE_STATE_PRIVATE,
        page_number,
    });
    assert!(resp.into_bits() == GhcbInfo::PAGE_STATE_UPDATED.0);

    // Accept the page, invalidates page state.
    pvalidate(page_number, ghcb_ptr as u64, false, true).expect("memory accept");

    // Flipping the C-bit makes the contents of the GHCB page scrambled,
    // zero it out.
    // SAFETY: the apge is statically-allocated, single-threaded access.
    unsafe {
        ghcb_ptr
            .as_mut()
            .expect("GHCB page is set")
            .as_mut_bytes()
            .fill(0);
    }
}

impl Ghcb {
    pub fn initialize() {
        // SAFETY: Always safe to read the GHCB MSR, no concurrency issues.
        GHCB_PREVIOUS.store(unsafe { read_msr(X86X_AMD_MSR_GHCB) }, Ordering::Release);

        map_ghcb_page();
        let page_number = GHCB.get() as u64;
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
    }

    pub fn uninitialize() {
        // SAFETY: Always safe to write the GHCB MSR, no concurrency issues.
        unsafe { write_msr(X86X_AMD_MSR_GHCB, GHCB_PREVIOUS.load(Ordering::Acquire)) };
        unmap_ghcb_page();
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

    #[inline(always)]
    fn vmgs_exit() {
        // SAFETY: Using the `vmgexit` instruction forces an exit to the hypervisor but doesn't
        // directly change program state.
        unsafe {
            asm!("rep vmmcall", options(nomem, nostack));
        }
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
            unsafe {
                write_msr(X86X_AMD_MSR_GHCB, ghcb_control.into_bits());
                Self::vmgs_exit();
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

    #[must_use]
    pub fn read_io_port(port: u16, access_size: u8) -> Option<u32> {
        let ghcb = Self::ghcb_mut();
        ghcb.ghcb_usage = GhcbUsage::BASE;
        ghcb.protocol_version = GhcbProtocolVersion::V2;
        ghcb.save.sw_exit_code = SevExitCode::IOIO.0;
        let io_exit_info = SevIoAccessInfo::new()
            .with_port(port)
            .with_read_access(true);
        let io_exit_info = match access_size {
            1 => io_exit_info.with_access_size8(true),
            2 => io_exit_info.with_access_size16(true),
            4 => io_exit_info.with_access_size32(true),
            _ => panic!("Invalid access size"),
        };
        ghcb.save.sw_exit_info1 = io_exit_info.into_bits().into();
        ghcb.save.sw_exit_info2 = 0;
        ghcb.save.valid_bitmap[0] = 0;
        ghcb.save.valid_bitmap[1] = (1u64 << (offset_of!(GhcbSaveArea, sw_exit_code) / 8 - 64))
            | (1u64 << (offset_of!(GhcbSaveArea, sw_exit_info1) / 8 - 64))
            | (1u64 << (offset_of!(GhcbSaveArea, sw_exit_info2) / 8 - 64));

        Self::ghcb_call(GhcbCall {
            info: GhcbInfo::NORMAL,
            extra_data: 0,
            page_number: GHCB.get() as u64,
        });

        ghcb.ghcb_usage = GhcbUsage::INVALID;

        if ghcb.save.sw_exit_info1 != 0 {
            None
        } else {
            Some(ghcb.save.rax as u32)
        }
    }

    #[must_use]
    pub fn write_io_port(port: u16, access_size: u8, data: u32) -> bool {
        let ghcb = Self::ghcb_mut();
        ghcb.ghcb_usage = GhcbUsage::BASE;
        ghcb.protocol_version = GhcbProtocolVersion::V2;
        ghcb.save.sw_exit_code = SevExitCode::IOIO.0;
        let io_exit_info = SevIoAccessInfo::new()
            .with_port(port)
            .with_read_access(false);
        let io_exit_info = match access_size {
            1 => io_exit_info.with_access_size8(true),
            2 => io_exit_info.with_access_size16(true),
            4 => io_exit_info.with_access_size32(true),
            _ => panic!("Invalid access size"),
        };
        ghcb.save.sw_exit_info1 = io_exit_info.into_bits().into();
        ghcb.save.sw_exit_info2 = 0;
        ghcb.save.rax = data as u64;
        ghcb.save.valid_bitmap[0] = 1u64 << offset_of!(GhcbSaveArea, rax) / 8;
        ghcb.save.valid_bitmap[1] = (1u64 << (offset_of!(GhcbSaveArea, sw_exit_code) / 8 - 64))
            | (1u64 << (offset_of!(GhcbSaveArea, sw_exit_info1) / 8 - 64))
            | (1u64 << (offset_of!(GhcbSaveArea, sw_exit_info2) / 8 - 64));

        Self::ghcb_call(GhcbCall {
            info: GhcbInfo::NORMAL,
            extra_data: 0,
            page_number: GHCB.get() as u64,
        });

        ghcb.ghcb_usage = GhcbUsage::INVALID;
        ghcb.save.sw_exit_info1 == 0
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

/// GHCB based io port access.
pub struct SnpIoAccess;

impl minimal_rt::arch::IoAccess for SnpIoAccess {
    unsafe fn inb(&self, port: u16) -> u8 {
        // Best effort
        Ghcb::read_io_port(port, 1).unwrap_or(!0) as u8
    }

    unsafe fn outb(&self, port: u16, data: u8) {
        // Best effort
        let _ = Ghcb::write_io_port(port, 1, data as u32);
    }
}

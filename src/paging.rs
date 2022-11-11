use core::arch::{
    asm,
    x86_64::{__cpuid, _mm_clflush},
};

use x86_64::{
    registers::control::Cr3,
    structures::paging::{PageSize, PageTable, PageTableFlags, PhysFrame, Size2MiB},
    PhysAddr,
};

// Amount of memory we identity map in setup(), max 512 GiB.
const ADDRESS_SPACE_GIB: usize = 4;
const TABLE: PageTable = PageTable::new();

#[derive(PartialEq)]
pub enum EncBitMode {
    Set,
    Clear,
}

// Put the Page Tables in static muts to make linking easier
#[no_mangle]
static mut L4_TABLE: PageTable = PageTable::new();
#[no_mangle]
static mut L3_TABLE: PageTable = PageTable::new();
#[no_mangle]
static mut L2_TABLES: [PageTable; ADDRESS_SPACE_GIB] = [TABLE; ADDRESS_SPACE_GIB];
#[no_mangle]
static mut SEV_ENC_BIT: [u64; 1] = [0];

pub fn setup() {
    // SAFETY: This function is idempontent and only writes to static memory and
    // CR3. Thus, it is safe to run multiple times or on multiple threads.
    let (l4, l3, l2s) = unsafe { (&mut L4_TABLE, &mut L3_TABLE, &mut L2_TABLES) };
    // log!("Setting up {} GiB identity mapping", ADDRESS_SPACE_GIB);
    let sev_enc_bit = unsafe { SEV_ENC_BIT[0] };
    if sev_enc_bit > 0 {
        log!("SEV Enabled - PTE mask: 0x{:x}", sev_enc_bit);
    }
    let pt_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    // Setup Identity map using L2 huge pages
    let mut next_addr = PhysAddr::new(0);
    for l2 in l2s.iter_mut() {
        for l2e in l2.iter_mut() {
            let addr = PhysAddr::new(next_addr.as_u64() | sev_enc_bit);
            l2e.set_addr(addr, pt_flags | PageTableFlags::HUGE_PAGE);
            next_addr += Size2MiB::SIZE;
        }
    }

    // Point L3 at L2s
    for (i, l2) in l2s.iter().enumerate() {
        let addr = phys_addr(l2).as_u64() | sev_enc_bit;
        let addr = PhysAddr::new(addr);
        l3[i].set_addr(addr, pt_flags);
    }

    // Point L4 at L3
    let addr = phys_addr(l3).as_u64() | sev_enc_bit;
    let addr = PhysAddr::new(addr);
    l4[0].set_addr(addr, pt_flags);

    // Point Cr3 at L4
    let (cr3_frame, cr3_flags) = Cr3::read();
    let l4_frame = PhysFrame::from_start_address(phys_addr(l4)).unwrap();
    if cr3_frame != l4_frame {
        unsafe { Cr3::write(l4_frame, cr3_flags) };
    }
}

pub fn set_or_clear_enc_bit(phys_addr: PhysAddr, len: u64, cache_flush: bool, mode: EncBitMode) {
    //Don't need to start from L4 because of identity map
    let l2s = unsafe { &mut L2_TABLES };
    //Get encryption mask
    let sev_enc_bit = unsafe { SEV_ENC_BIT[0] };
    if cache_flush {
        invalidate_data_cache_range(phys_addr, len);
    }

    let base_addr = phys_addr.as_u64() - (phys_addr.as_u64() % Size2MiB::SIZE);

    let mut num_pages = 1;
    if len > Size2MiB::SIZE {
        num_pages = ( len / Size2MiB::SIZE) + 
            if (len % Size2MiB::SIZE) > 0 {
                1
            } else {
                0
            }
    }

    //log!("{} C bit on {} pages", mode_str, num_pages);
    let mut l2_off = (base_addr >> 30) & 0x01ff;
    let mut pte_off = (base_addr >> 21) & 0x01ff;
    assert!(pte_off < 512);
    assert!(l2_off < l2s.len() as u64);

    while num_pages != 0 {
        //get page of page table
        let table = &mut l2s[l2_off as usize];
        //get page table entry
        let entry = &mut table[pte_off as usize];
        //clear Cbit
        let new_addr = match mode {
            EncBitMode::Clear => entry.addr().as_u64() & !sev_enc_bit,
            EncBitMode::Set => entry.addr().as_u64() | sev_enc_bit,
        };
        //set new pte
        entry.set_addr(PhysAddr::new(new_addr), entry.flags());

        num_pages -= 1;
        pte_off += 1;
        //Go to next page of page table
        if pte_off >= 512 {
            l2_off += 1;
            pte_off = 0;
        }
    }
    // flush tlb
    let (base, flags) = Cr3::read();
    unsafe { Cr3::write(base, flags) };
}

fn invalidate_data_cache_range(phys_addr: PhysAddr, len: u64) {
    //Check if cpu supports clflush
    let result = unsafe { __cpuid(0x01) };
    if result.edx & 0x80000 == 0 {
        unsafe { asm!("wbinvd",) }
    }

    let cache_line_size = (result.ebx & 0xff00) >> 5;
    let mut start = phys_addr.as_u64();
    let end = (start + len + (cache_line_size as u64 - 1)) & !(cache_line_size as u64 - 1);
    start = start & !(cache_line_size as u64 - 1);

    loop {
        asm_flush_cache_line(start);
        start += cache_line_size as u64;
        if start == end {
            break;
        };
    }
}

fn asm_flush_cache_line(addr: u64) {
    unsafe { _mm_clflush(addr as *const _) }
}

// Map a virtual address to a PhysAddr (assumes identity mapping)
fn phys_addr<T>(virt_addr: *const T) -> PhysAddr {
    PhysAddr::new(virt_addr as u64)
}

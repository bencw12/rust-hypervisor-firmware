use x86_64::{
    instructions::hlt,
    registers::control::Cr3,
    structures::paging::{PageSize, PageTable, PageTableFlags, PhysFrame, Size2MiB},
    PhysAddr,
};

use x86_64::instructions::port::Port;

use crate::boot::boot_e820_entry;
use crate::ghcb::GHCB_ADDR;
// Amount of memory we identity map in setup(), max 512 GiB.
#[no_mangle]
static ADDRESS_SPACE_GIB_COPY: u32 = 1;

const ADDRESS_SPACE_GIB: usize = 1;
const TABLE: PageTable = PageTable::new();
// Put the Page Tables in static muts to make linking easier
#[no_mangle]
pub static mut L4_TABLE: PageTable = PageTable::new();
#[no_mangle]
pub static mut L3_TABLE: PageTable = PageTable::new();
#[no_mangle]
pub static mut L2_TABLES: [PageTable; ADDRESS_SPACE_GIB] = [TABLE; ADDRESS_SPACE_GIB];
#[no_mangle]
static SEV_ENC_BIT: u64 = 1 << 51;

pub fn setup(plain_text: bool) {
    // SAFETY: This function is idempontent and only writes to static memory and
    // CR3. Thus, it is safe to run multiple times or on multiple threads.
    let (l4, l3, l2s) = unsafe { (&mut L4_TABLE, &mut L3_TABLE, &mut L2_TABLES) };

    let pt_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    // Setup Identity map using L2 huge pages
    let mut next_addr = PhysAddr::new(0);
    for l2 in l2s.iter_mut() {
        for l2e in l2.iter_mut() {
            //leave C-bit clear on [16MB, 34MB) (8 pages for bzimage and 1 page for GHCB)
            let addr = if (next_addr.as_u64() >= 8 * Size2MiB::SIZE)
                && (next_addr.as_u64() <= GHCB_ADDR as u64)
                && plain_text
            {
                PhysAddr::new(next_addr.as_u64())
            } else {
                PhysAddr::new(next_addr.as_u64() | SEV_ENC_BIT)
            };
            l2e.set_addr(addr, pt_flags | PageTableFlags::HUGE_PAGE);
            next_addr += Size2MiB::SIZE;
        }
    }

    // Point L3 at L2s
    for (i, l2) in l2s.iter().enumerate() {
        let addr = phys_addr(l2).as_u64() | SEV_ENC_BIT;
        let addr = PhysAddr::new(addr);
        l3[i].set_addr(addr, pt_flags);
    }

    // Point L4 at L3
    let addr = phys_addr(l3).as_u64() | SEV_ENC_BIT;
    let addr = PhysAddr::new(addr);
    l4[0].set_addr(addr, pt_flags);

    // Point Cr3 at L4
    let (cr3_frame, cr3_flags) = Cr3::read();
    let l4_frame = PhysFrame::from_start_address(phys_addr(l4)).unwrap();
    if cr3_frame != l4_frame {
        unsafe { Cr3::write(l4_frame, cr3_flags) };
    }
}

pub fn pvalidate_ram(e820_entry: &boot_e820_entry, stack_start: u64, plain_text: bool) {
    let start = e820_entry.addr;
    let mut size = e820_entry.size;

    assert!(start & 0xfff == 0);

    const CPUID_PAGE_ADDR: u64 = 0x1000; // 4K
    const ZERO_PAGE_START: u64 = 0x7000; // 28K
    const FIRMWARE_START: u64 = 0x100000; // 1M
    const KERNEL_HASH_START: u64 = FIRMWARE_START - 0x1000; //1M - 4K
    const KERNEL_PLAIN_TEXT: u64 = 0x1000000; // 16M
    const KERNEL_CMDLINE: u64 = 0x20000; //128K
    const GHCB_PAGE: u64 = 0x2000000; // 32M
    const STACK_SIZE: u64 = 0x20000;
    size = size & !0xfff;

    let mut npgs = size >> 12;
    let mut start_pg = start >> 12;

    while npgs > 0 {
        // skip cpuid page
        if start_pg == CPUID_PAGE_ADDR >> 12 {
            start_pg += 1;
            npgs -= 1;
        }
        // //skip zero page
        if start_pg == ZERO_PAGE_START >> 12 {
            start_pg += 1;
            npgs -= 1;
        }
        // //skip hash
        if start_pg == KERNEL_HASH_START >> 12 {
            start_pg += 1;
            npgs -= 1;
        }
        // //skip firmware
        if start_pg == FIRMWARE_START >> 12 {
            start_pg += 4;
            npgs -= 4;
        }
        // //skip plain text kernel
        if start_pg == (KERNEL_PLAIN_TEXT >> 12) && plain_text {
            start_pg += (8 * Size2MiB::SIZE) >> 12;
            npgs -= (8 * Size2MiB::SIZE) >> 12;
        }
        // //skip kernel cmdline
        if start_pg == KERNEL_CMDLINE >> 12 {
            start_pg += 1;
            npgs -= 1;
        }
        // //skip over ghcb page if
        if start_pg == (GHCB_PAGE >> 12) && plain_text {
            start_pg += 512;
            npgs -= 512;
        }

        //skip over page tables this works because this is the order they're defined in
        if start_pg == unsafe { &L4_TABLE as *const _ as u64 } >> 12 {
            start_pg += 1;
            npgs -= 1;
        }
        if start_pg == unsafe { &L3_TABLE as *const _ as u64 } >> 12 {
            start_pg += 1;
            npgs -= 1;
        }
        if start_pg == unsafe { L2_TABLES.as_ptr() as *const _ as u64 } >> 12 {
            start_pg += 1;
            npgs -= 1;
        }
        // skip stack
        // the stack is 128k from layout.ld
        if start_pg == (stack_start - STACK_SIZE) >> 12 {
            start_pg += 128 / 4;
            npgs -= 128 / 4;
        }

        pvalidate(start_pg, 1);

        start_pg += 1;
        npgs -= 1;
    }
}

pub fn pvalidate(start: u64, valid: u32) {
    //start is the page number (4k pages) that we are validating
    let addr = start << 12;
    let page_size = 0;
    let mut cf: u8;
    let mut rc: u32;

    let mut debug_port = Port::<u8>::new(0x80);

    unsafe {
        core::arch::asm!(
            "pvalidate",
            "setc dl",
            in("rax") addr,
            in("ecx") page_size,
            in("edx") valid,
            lateout("eax") rc,
            lateout("dl") cf,
            options(nomem, nostack)
        );
    }

    if rc == 1 {
        unsafe { debug_port.write(0x88 as u8) };
        loop {
            hlt();
        }
    }
    if cf == 1 {
        unsafe { debug_port.write(0x89 as u8) };
        loop {
            hlt();
        }
    }
}

// Map a virtual address to a PhysAddr (assumes identity mapping)
fn phys_addr<T>(virt_addr: *const T) -> PhysAddr {
    PhysAddr::new(virt_addr as u64)
}

use x86_64::{
    registers::control::Cr3,
    structures::paging::{PageSize, PageTable, PageTableFlags, PhysFrame, Size2MiB},
    PhysAddr,
};

use crate::{fw_cfg::KERNEL_ADDR, fw_cfg::KERNEL_MAX_SIZE, ghcb::GHCB_ADDR};
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

pub fn setup(plain_text: bool, initrd_plain_text_addr: u64, initrd_size_aligned: u64) {
    // SAFETY: This function is idempontent and only writes to static memory and
    // CR3. Thus, it is safe to run multiple times or on multiple threads.
    let (l4, l3, l2s) = unsafe { (&mut L4_TABLE, &mut L3_TABLE, &mut L2_TABLES) };

    let pt_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    // Setup Identity map using L2 huge pages
    let mut next_addr = PhysAddr::new(0);
    for l2 in l2s.iter_mut() {
        for l2e in l2.iter_mut() {
            //leave C-bit clear on [16MB, 34MB) (8 pages for bzimage and 1 page for GHCB)
            let addr = if (((next_addr.as_u64() >= KERNEL_ADDR)
                && (next_addr.as_u64() <= GHCB_ADDR as u64))
                || ((next_addr.as_u64() >= initrd_plain_text_addr)
                    && (next_addr.as_u64() < initrd_plain_text_addr + initrd_size_aligned)))
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

// Map a virtual address to a PhysAddr (assumes identity mapping)
fn phys_addr<T>(virt_addr: *const T) -> PhysAddr {
    PhysAddr::new(virt_addr as u64)
}

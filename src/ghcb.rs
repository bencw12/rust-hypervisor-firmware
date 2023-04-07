use x86_64::structures::paging::{PageSize, Size2MiB};

use crate::mem::MemoryRegion;

pub const GHCB_ADDR: u64 = 16 * Size2MiB::SIZE;
pub const GHCB_MSR: u32 = 0xC001_0130;

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
//The ghcb page
pub struct Ghcb {
    reserved1: [u8; 0xcb],
    cpl: u8,
    reserved2: [u8; 0x74],
    xss: u64,
    reserved3: [u8; 0x18],
    dr7: u64,
    reserved4: [u8; 0x90],
    pub rax: u64,
    reserved5: [u8; 0x100],
    reserved6: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    reserved7: [u8; 0x70],
    pub sw_exitcode: u64,
    pub sw_exitinfo1: u64,
    pub sw_exitinfo2: u64,
    pub sw_scratch: u64,
    reserved8: [u8; 0x38],
    pub xcr0: u64,
    valid_bitmap: [u8; 0x10],
    x86_state_gpa: u64,
    reserved9: [u8; 0x3f8],
    shared_buf: [u8; 0x7f0],
    reserved10: [u8; 0x0a],
    protocol_version: u16,
    ghcb_usage: u32,
}

static mut GHCB: Ghcb = Ghcb::new();
static mut GHCB_PAGE: MemoryRegion =
    MemoryRegion::new(GHCB_ADDR, core::mem::size_of::<Ghcb>() as u64);

pub fn register_ghcb_page() {
    let mut ghcb_msr = x86_64::registers::model_specific::Msr::new(GHCB_MSR);
    //write GPA of GHCB page to GHCB MSR
    unsafe { ghcb_msr.write(GHCB_ADDR) };
}

impl Ghcb {
    #[inline]
    const fn new() -> Self {
        Ghcb {
            reserved1: [0u8; 0xcb],
            cpl: 0u8,
            reserved2: [0u8; 0x74],
            xss: 0u64,
            reserved3: [0u8; 0x18],
            dr7: 0u64,
            reserved4: [0u8; 0x90],
            rax: 0u64,
            reserved5: [0u8; 0x100],
            reserved6: 0u64,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            reserved7: [0u8; 0x70],
            sw_exitcode: 0,
            sw_exitinfo1: 0,
            sw_exitinfo2: 0,
            sw_scratch: 0,
            reserved8: [0; 0x38],
            xcr0: 0,
            valid_bitmap: [0; 0x10],
            x86_state_gpa: 0,
            reserved9: [0; 0x3f8],
            shared_buf: [0; 0x7f0],
            reserved10: [0; 0x0a],
            protocol_version: 0,
            ghcb_usage: 0,
        }
    }
    //Write ghcb struct to ghcb page
    pub fn port_io(port: u16, value: u8) {
        let rax: u64 = value as u64;
        let exitinfo1: u64 = ((port as u64) << 16) | 0x10;

        let rax_offset = 0x01f8 / 8;
        let rax_byte_offset = rax_offset / 8;
        let rax_bit_position = rax_offset % 8;

        let exitcode_offset: usize = 0x0390 / 8;
        let exitcode_byte_offset: usize = exitcode_offset / 8;
        let exitcode_bit_position: usize = exitcode_offset % 8;

        let exitinfo1_offset: usize = 0x0398 / 8;
        let exitinfo1_byte_offset: usize = exitinfo1_offset / 8;
        let exitinfo1_bit_position: usize = exitinfo1_offset % 8;

        let exitinfo2_offset: usize = 0x03a0 / 8;
        let exitinfo2_byte_offset: usize = exitinfo2_offset / 8;
        let exitinfo2_bit_position: usize = exitinfo2_offset % 8;

        let scratch_offset: usize = 0x03a8 / 8;
        let scratch_byte_offset: usize = scratch_offset / 8;
        let scratch_bit_position: usize = scratch_byte_offset % 8;

        unsafe {
            //rax is the value we're writing to the port
            GHCB.protocol_version = 2;
            GHCB.rax = rax;
            GHCB.sw_exitcode = 0x7b;
            GHCB.sw_exitinfo1 = exitinfo1;
            GHCB.sw_exitinfo2 = 0;
            GHCB.sw_scratch = 0;
            GHCB.valid_bitmap = [0x0u8; 16];
            GHCB.ghcb_usage = 0;

            //set valid bits
            GHCB.valid_bitmap[rax_byte_offset as usize] =
                GHCB.valid_bitmap[rax_byte_offset as usize] | (1 << rax_bit_position as usize);

            GHCB.valid_bitmap[exitcode_byte_offset as usize] = GHCB.valid_bitmap
                [exitcode_byte_offset as usize]
                | (1 << exitcode_bit_position as usize);

            GHCB.valid_bitmap[exitinfo1_byte_offset as usize] = GHCB.valid_bitmap
                [exitinfo1_byte_offset as usize]
                | (1 << exitinfo1_bit_position as usize);

            GHCB.valid_bitmap[exitinfo2_byte_offset as usize] = GHCB.valid_bitmap
                [exitinfo2_byte_offset as usize]
                | (1 << exitinfo2_bit_position as usize);

            GHCB.valid_bitmap[scratch_byte_offset as usize] = GHCB.valid_bitmap
                [scratch_byte_offset as usize]
                | (1 << scratch_bit_position as usize);

            //write ghcb to reserved page
            GHCB_PAGE
                .as_bytes()
                .copy_from_slice(core::slice::from_raw_parts(
                    (&GHCB as *const Ghcb) as *const u8,
                    core::mem::size_of::<Ghcb>(),
                ));
        }
    }
}

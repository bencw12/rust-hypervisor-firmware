use core::mem::{size_of, transmute, zeroed};

pub const HEADER_START: usize = 0x1f1;
const HEADER_END: usize = HEADER_START + size_of::<Header>();

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct boot_e820_entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Header {
    pub setup_sects: u8,
    pub root_flags: u16,
    pub syssize: u32,
    pub ram_size: u16,
    pub vid_mode: u16,
    pub root_dev: u16,
    pub boot_flag: u16,
    pub jump: u16,
    pub header: u32,
    pub version: u16,
    pub realmode_swtch: u32,
    pub start_sys_seg: u16,
    pub kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: u8,
    pub setup_move_size: u16,
    pub code32_start: u32,
    pub ramdisk_image: u32,
    pub ramdisk_size: u32,
    pub bootsect_kludge: u32,
    pub heap_end_ptr: u16,
    pub ext_loader_ver: u8,
    pub ext_loader_type: u8,
    pub cmd_line_ptr: u32,
    pub initrd_addr_max: u32,
    pub kernel_alignment: u32,
    pub relocatable_kernel: u8,
    pub min_alignment: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub hardware_subarch: u32,
    pub hardware_subarch_data: u64,
    pub payload_offset: u32,
    pub payload_length: u32,
    pub setup_data: u64,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
    pub kernel_info_offset: u32,
}

impl Header {
    pub fn from_slice(f: &[u8]) -> Self {
        let mut data: [u8; 1024] = [0; 1024];
        data.copy_from_slice(f);
        #[repr(C)]
        struct HeaderData {
            before: [u8; HEADER_START],
            hdr: Header,
            after: [u8; 1024 - HEADER_END],
        }
        // SAFETY: Struct consists entirely of primitive integral types.
        unsafe { transmute::<_, HeaderData>(data) }.hdr
    }
}

impl Default for Header {
    fn default() -> Self {
        // SAFETY: Struct consists entirely of primitive integral types.
        unsafe { zeroed() }
    }
}

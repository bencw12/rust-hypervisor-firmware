use core::mem;

pub const PT_LOAD: u32 = 1;

#[allow(non_camel_case_types)]
type Elf64_Addr = __u64;
#[allow(non_camel_case_types)]
type Elf64_Half = __u16;
#[allow(non_camel_case_types)]
type Elf64_Off = __u64;
#[allow(non_camel_case_types)]
type Elf64_Word = __u32;
#[allow(non_camel_case_types)]
type Elf64_Xword = __u64;

#[allow(non_camel_case_types)]
type __s8 = i8;
#[allow(non_camel_case_types)]
type __u8 = u8;
#[allow(non_camel_case_types)]
type __s16 = i16;
#[allow(non_camel_case_types)]
type __u16 = u16;
#[allow(non_camel_case_types)]
type __s32 = i32;
#[allow(non_camel_case_types)]
type __u32 = u32;
#[allow(non_camel_case_types)]
type __s64 = i64;
#[allow(non_camel_case_types)]
type __u64 = u64;

#[repr(C)]
#[derive(Debug, Default, Copy)]
pub struct elf64_hdr {
    pub e_ident: [u8; 16usize],
    pub e_type: Elf64_Half,
    pub e_machine: Elf64_Half,
    pub e_version: Elf64_Word,
    pub e_entry: Elf64_Addr,
    pub e_phoff: Elf64_Off,
    pub e_shoff: Elf64_Off,
    pub e_flags: Elf64_Word,
    pub e_ehsize: Elf64_Half,
    pub e_phentsize: Elf64_Half,
    pub e_phnum: Elf64_Half,
    pub e_shentsize: Elf64_Half,
    pub e_shnum: Elf64_Half,
    pub e_shstrndx: Elf64_Half,
}

impl Clone for elf64_hdr {
    fn clone(&self) -> Self {
        *self
    }
}
#[allow(non_camel_case_types)]
pub type Elf64_Ehdr = elf64_hdr;

impl Elf64_Ehdr {
    pub fn from_slice(f: &[u8]) -> Self {
        let mut data: [u8; mem::size_of::<Elf64_Ehdr>()] = [0; mem::size_of::<Elf64_Ehdr>()];
        for x in 0..mem::size_of::<Elf64_Ehdr>() {
            data[x] = f[x];
        }
        unsafe { mem::transmute::<_, Elf64_Ehdr>(data) }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy)]
pub struct elf64_phdr {
    pub p_type: Elf64_Word,
    pub p_flags: Elf64_Word,
    pub p_offset: Elf64_Off,
    pub p_vaddr: Elf64_Addr,
    pub p_paddr: Elf64_Addr,
    pub p_filesz: Elf64_Xword,
    pub p_memsz: Elf64_Xword,
    pub p_align: Elf64_Xword,
}

impl Clone for elf64_phdr {
    fn clone(&self) -> Self {
        *self
    }
}
#[allow(non_camel_case_types)]
pub type Elf64_Phdr = elf64_phdr;

impl Elf64_Phdr {
    pub fn from_slice(f: &[u8]) -> Self {
        let mut data: [u8; mem::size_of::<Elf64_Phdr>()] = [0; mem::size_of::<Elf64_Phdr>()];
        for x in 0..mem::size_of::<Elf64_Phdr>() {
            data[x] = f[x];
        }
        unsafe { mem::transmute::<_, Elf64_Phdr>(data) }
    }
}
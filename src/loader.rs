// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use atomic_refcell::AtomicRefCell;

use crate::{
    boot::{Header, Info, Params},
    mem::{MemoryRegion},
};

#[derive(Debug)]
pub enum Error {
    MagicMissing,
    NotRelocatable,
    E820Configuration
}

pub const KERNEL_LOAD: u64 = 0x20_0000;
const ZERO_PAGE_START: u64 = 0x7000;
pub const HASH_SIZE_BYTES: u64 = 32;
pub const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
pub const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
pub const KERNEL_LOADER_OTHER: u8 = 0xff;
pub const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.
pub const CMDLINE_START: u64 = 0x4b000;
pub const CMDLINE_MAX_LEN: u64 = 0x10000;
pub const EBDA_START: u64 = 0xa0000;
pub const E820_RAM: u32 = 1;

pub struct Kernel {
    pub params: Params, 
    pub entry_point: u64,
}

impl Kernel {
    pub fn new(info: &dyn Info) -> Self {
        let mut kernel = Self {
            params: Params::default(), 
            entry_point: 0,
        };
        kernel.params.acpi_rsdp_addr = info.rsdp_addr();
        kernel.params.set_entries(info);
        kernel
    }

    pub fn write_params(&mut self) {
        let params_addr = &mut self.params as *mut _ as u64;
        let boot_params_len = core::mem::size_of::<Params>();
        let mut params_region = MemoryRegion::new(params_addr, boot_params_len as u64);
        let mut zero_page = MemoryRegion::new(ZERO_PAGE_START, boot_params_len as u64);

        zero_page.as_bytes()[0..boot_params_len].copy_from_slice(&params_region.as_bytes());
    }

    pub fn add_e820_entry(
        &mut self,
        addr: u64,
        size: u64,
        mem_type: u32,
    ) -> Result<(), Error> {
        if self.params.e820_entries >= self.params.e820_table.len() as u8 {
            return Err(Error::E820Configuration);
        }
    
        self.params.e820_table[self.params.e820_entries as usize].addr = addr;
        self.params.e820_table[self.params.e820_entries as usize].size = size;
        self.params.e820_table[self.params.e820_entries as usize].entry_type = mem_type;
        self.params.e820_entries += 1;
    
        Ok(())
    }

    pub fn load_bzimage_from_payload(&mut self, kernel: &mut MemoryRegion) -> Result<(), Error> {
        let mut header = [0u8; 1024];
        for i in 0..1024 {
            header[i] = kernel.read_u8(i as u64);
        }
        self.params.hdr = Header::from_slice(&header);
        if self.params.hdr.boot_flag != 0xAA55 || self.params.hdr.header != u32::from_le_bytes(*b"HdrS") {
            return Err(Error::MagicMissing);
        }
        // Check relocatable
        if self.params.hdr.version < 0x205 || self.params.hdr.relocatable_kernel == 0 {
            return Err(Error::NotRelocatable);
        }
        // Skip over the setup sectors
        let setup_sects = match self.params.hdr.setup_sects {
            0 => 4,
            n => n as u32,
        };

        let setup_bytes = (setup_sects + 1) * 512;
        let remaining_bytes = kernel.as_bytes().len() as u32 - setup_bytes;
        let mut region = MemoryRegion::new(KERNEL_LOAD, remaining_bytes as u64);
        let remaining: &mut [u8] = kernel.as_mut_slice(setup_bytes as u64, remaining_bytes as u64);
        //Copy kernel to correct location
        region.as_bytes()[..remaining.len()].copy_from_slice(remaining);
    
        self.params.hdr.type_of_loader = 0xff;
        self.params.hdr.code32_start = KERNEL_LOAD as u32;
        self.params.hdr.cmd_line_ptr = CMDLINE_START as u32;
        self.entry_point = self.params.hdr.code32_start as u64 + 0x200;
    
        self.write_params();

        Ok(())
    }

    pub fn append_cmdline(&mut self, addition: &[u8]) {
        if !addition.is_empty() {
            CMDLINE.borrow_mut().append(addition);
            assert!(CMDLINE.borrow().len() < self.params.hdr.cmdline_size);
        }
    }

    pub fn boot(&mut self) {

        // pub const BOOT_STACK_POINTER: u64 = 0x8ff0;

        // 0x200 is the startup_64 offset
        let jump_address = self.entry_point;
        log!("Jumping to: 0x{:x}", jump_address);
        // Rely on x86 C calling convention where second argument is put into %rsi register
        let ptr = jump_address as *const ();
        let code: extern "C" fn(u64, u64) = unsafe { core::mem::transmute(ptr) };
        (code)(0 /* dummy value */, ZERO_PAGE_START );
    }
}

static CMDLINE: AtomicRefCell<CmdLine> = AtomicRefCell::new(CmdLine::new());

struct CmdLine {
    region: MemoryRegion,
    length: usize, // Does not include null pointer
}

impl CmdLine {
    const fn new() -> Self {
        Self {
            region: MemoryRegion::new(CMDLINE_START, CMDLINE_MAX_LEN),
            length: 0,
        }
    }

    const fn len(&self) -> u32 {
        self.length as u32
    }

    fn append(&mut self, args: &[u8]) {
        let bytes = self.region.as_bytes();
        bytes[self.length] = b' ';
        self.length += 1;

        bytes[self.length..self.length + args.len()].copy_from_slice(args);
        self.length += args.len();
        bytes[self.length] = 0;
    }
}

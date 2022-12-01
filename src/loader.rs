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
use crate::{
    boot::Header,
    boot::HEADER_START,
    mem::MemoryRegion,
};

#[derive(Debug)]
pub enum Error {
    MagicMissing,
    NotRelocatable,
}

pub const KERNEL_LOAD: u64 = 0x20_0000;
const ZERO_PAGE_START: u64 = 0x7000;
pub const HASH_SIZE_BYTES: u64 = 32;
pub const CMDLINE_START: u64 = 0x20000;

pub struct Kernel {
    pub hdr: Header, 
    pub entry_point: u64,
}

impl Kernel {
    pub fn new() -> Self {
        let kernel = Self {
            hdr: Header::default(), 
            entry_point: 0,
        };
        kernel
    }

    pub fn write_params(&mut self) {
        let params_addr = &mut self.hdr as *mut _ as u64;
        let mut params_region = MemoryRegion::new(params_addr, core::mem::size_of::<Header>() as u64);
        let mut zero_page = MemoryRegion::new(ZERO_PAGE_START + HEADER_START as u64, core::mem::size_of::<Header>() as u64);

        zero_page.as_bytes().copy_from_slice(&params_region.as_bytes());
    }

    pub fn load_bzimage_from_payload(&mut self, kernel: &mut MemoryRegion) -> Result<(), Error> {
        let mut header = [0u8; 1024];
        for i in 0..1024 {
            header[i] = kernel.read_u8(i as u64);
        }
        self.hdr = Header::from_slice(&header);
        if self.hdr.boot_flag != 0xAA55 || self.hdr.header != u32::from_le_bytes(*b"HdrS") {
            log!("Magic missing");
            return Err(Error::MagicMissing);
        }
        // Check relocatable

        if self.hdr.version < 0x205 || self.hdr.relocatable_kernel == 0 {
            log!("Not relocatable");
            return Err(Error::NotRelocatable);
        }
        

        // Skip over the setup sectors
        let setup_sects = match self.hdr.setup_sects {
            0 => 4,
            n => n as u32,
        };

        let setup_bytes = (setup_sects + 1) * 512;
        let remaining_bytes = kernel.as_bytes().len() as u32 - setup_bytes;
        let mut region = MemoryRegion::new(KERNEL_LOAD, remaining_bytes as u64);
        let remaining: &mut [u8] = kernel.as_mut_slice(setup_bytes as u64, remaining_bytes as u64);
        //Copy kernel to correct location
        region.as_bytes()[..remaining.len()].copy_from_slice(remaining);
    
        self.hdr.type_of_loader = 0xff;
        self.hdr.code32_start = KERNEL_LOAD as u32;
        self.hdr.cmd_line_ptr = CMDLINE_START as u32;
        self.entry_point = self.hdr.code32_start as u64 + 0x200;
    
        self.write_params();

        Ok(())
    }

    pub fn boot(&mut self) {

        let jump_address = self.entry_point;
        log!("Jumping to: 0x{:x}", jump_address);
        log!("TEST");

        // Rely on x86 C calling convention where second argument is put into %rsi register
        let ptr = jump_address as *const ();
        let code: extern "C" fn(u64, u64) = unsafe { core::mem::transmute(ptr) };
        (code)(0 /* dummy value */, ZERO_PAGE_START );
    }
}
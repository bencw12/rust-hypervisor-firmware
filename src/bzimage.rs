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
    mem::MemoryRegion,
};

#[derive(Debug)]
pub enum Error {
    MagicMissing,
    NotRelocatable,
}

pub const KERNEL_LOCATION: u64 = 0x2000000;
const KERNEL_LOAD: u64 = 0x20_0000;

#[repr(transparent)]
pub struct Kernel(Params);

impl Kernel {
    pub fn new(info: &dyn Info) -> Self {
        let mut kernel = Self(Params::default());
        kernel.0.acpi_rsdp_addr = info.rsdp_addr();
        kernel.0.set_entries(info);
        kernel
    }

    pub fn load_kernel_from_payload(&mut self, kernel: &mut MemoryRegion) -> Result<(), Error> {
        let mut header = [0u8; 1024];
        for i in 0..1024 {
            header[i] = kernel.read_u8(i as u64);
        }
        self.0.hdr = Header::from_slice(&header);
        if self.0.hdr.boot_flag != 0xAA55 || self.0.hdr.header != *b"HdrS" {
            return Err(Error::MagicMissing);
        }
        // Check relocatable
        if self.0.hdr.version < 0x205 || self.0.hdr.relocatable_kernel == 0 {
            return Err(Error::NotRelocatable);
        }
        // Skip over the setup sectors
        let setup_sects = match self.0.hdr.setup_sects {
            0 => 4,
            n => n as u32,
        };

        let setup_bytes = (setup_sects + 1) * 512;
        let remaining_bytes = kernel.as_bytes().len() as u32 - setup_bytes;
        let region = MemoryRegion::new(KERNEL_LOAD, remaining_bytes as u64);
        let remaining: &mut [u8] = kernel.as_mut_slice(setup_bytes as u64, remaining_bytes as u64);
        //Copy kernel to correct location
        for i in 0..remaining.len() {
            region.write_u8(i as u64, remaining[i]);
        }
        self.0.hdr.type_of_loader = 0xff;
        self.0.hdr.code32_start = KERNEL_LOAD as u32;
        self.0.hdr.cmd_line_ptr = CMDLINE_START as u32;
        Ok(())
    }

    pub fn append_cmdline(&mut self, addition: &[u8]) {
        if !addition.is_empty() {
            CMDLINE.borrow_mut().append(addition);
            assert!(CMDLINE.borrow().len() < self.0.hdr.cmdline_size);
        }
    }

    pub fn boot(&mut self) {
        // 0x200 is the startup_64 offset
        let jump_address = self.0.hdr.code32_start as u64 + 0x200;
        // Rely on x86 C calling convention where second argument is put into %rsi register
        let ptr = jump_address as *const ();
        let code: extern "C" fn(u64, u64) = unsafe { core::mem::transmute(ptr) };
        (code)(0 /* dummy value */, &mut self.0 as *mut _ as u64);
    }
}

// This is the highest region at which we can load the kernel command line.
const CMDLINE_START: u64 = 0x4b000;
const CMDLINE_MAX_LEN: u64 = 0x10000;

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

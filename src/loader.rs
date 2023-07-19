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
    boot::{CCBlob, HEADER_START, SETUP_CC_BLOB},
    boot::{Header, SetupData},
    mem::MemoryRegion,
};

#[derive(Debug)]
pub enum Error {
    MagicMissing,
    NotRelocatable,
}

pub const KERNEL_LOAD: u32 = 0x200_000;
pub const ZERO_PAGE_START: u64 = 0x7000;
pub const HASH_SIZE_BYTES: u64 = 32;
pub const CMDLINE_START: u64 = 0x20000;
pub const E820_ENTRIES_OFFSET: u64 = 0x1e8;
pub const E820_TABLE_OFFSET: u64 = 0x2d0;
pub const CPUID_PAGE_ADDR: u64 = 0x1000;
pub const CPUID_PAGE_LEN: u64 = 0x1000;
pub const SECRETS_PAGE_ADDR: u64 = 0x2000;
pub const SECRETS_PAGE_LEN: u64 = 0x1000;

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
        let mut params_region =
            MemoryRegion::new(params_addr, core::mem::size_of::<Header>() as u64);
        let mut zero_page = MemoryRegion::new(
            ZERO_PAGE_START + HEADER_START as u64,
            core::mem::size_of::<Header>() as u64,
        );

        zero_page
            .as_bytes()
            .copy_from_slice(&params_region.as_bytes());
    }

    pub fn load_bzimage_from_payload(
        &mut self,
        kernel: &mut MemoryRegion,
        initrd_addr: u32,
        initrd_size: u32,
    ) -> Result<(), Error> {
        let mut header = [0u8; 1024];
        for i in 0..1024 {
            header[i] = kernel.read_u8(i as u64);
        }
        self.hdr = Header::from_slice(&header);
        if self.hdr.boot_flag != 0xAA55 || self.hdr.header != u32::from_le_bytes(*b"HdrS") {
            return Err(Error::MagicMissing);
        }
        // Check relocatable
        if self.hdr.version < 0x205 || self.hdr.relocatable_kernel == 0 {
            return Err(Error::NotRelocatable);
        }

        // Skip over the setup sectors
        let setup_sects = match self.hdr.setup_sects {
            0 => 4,
            n => n as u32,
        };

        let setup_bytes = (setup_sects + 1) * 512;

        self.hdr.type_of_loader = 0xff;
        self.hdr.code32_start = KERNEL_LOAD + setup_bytes;
        self.hdr.cmd_line_ptr = CMDLINE_START as u32;
        self.entry_point = self.hdr.code32_start as u64 + 0x200;

        self.hdr.ramdisk_image = initrd_addr;
        self.hdr.ramdisk_size = initrd_size;

        if self.hdr.setup_data == 0 {
            const SETUP_DATA_LEN: u64 = core::mem::size_of::<SetupData>() as u64;
            const CCBLOB_LEN: u64 = core::mem::size_of::<CCBlob>() as u64;
            const CCBLOB_MAGIC: u32 = 0x45444d41;
            //end of the zero page
            let setup_data_addr = (ZERO_PAGE_START + CPUID_PAGE_LEN) - SETUP_DATA_LEN - CCBLOB_LEN;
            let cc_blob_addr = ((ZERO_PAGE_START + CPUID_PAGE_LEN) - CCBLOB_LEN) as u32;

            let setup_data = SetupData {
                next: 0,              //only setup data node in the list
                _type: SETUP_CC_BLOB, //CC setup data blob type
                len: 4,               //4 bytes because cc_blob_addr is u32
                cc_blob_addr,
            };

            let cc_blob = CCBlob {
                magic: CCBLOB_MAGIC,
                version: 0,
                reserved: 0,
                secrets_phys: SECRETS_PAGE_ADDR,
                secrets_len: SECRETS_PAGE_LEN as u32,
                reserved1: 0,
                cpuid_phys: CPUID_PAGE_ADDR,
                cpuid_len: 4096,
                reserved2: 0,
            };

            let mut setup_data_region =
                MemoryRegion::new(setup_data_addr as u64, SETUP_DATA_LEN as u64);

            setup_data_region
                .as_mut_slice(0, SETUP_DATA_LEN as u64)
                .copy_from_slice(&setup_data.as_slice());

            let mut cc_blob_region = MemoryRegion::new(cc_blob_addr as u64, CCBLOB_LEN as u64);

            cc_blob_region
                .as_mut_slice(0, CCBLOB_LEN as u64)
                .copy_from_slice(&cc_blob.as_slice());

            //point to the node
            self.hdr.setup_data = setup_data_addr as u64;
        }

        self.write_params();

        Ok(())
    }

    pub fn boot(&mut self) {
        let jump_address = self.entry_point;

        // Rely on x86 C calling convention where second argument is put into %rsi register
        let ptr = jump_address as *const ();
        let code: extern "C" fn(u64, u64) = unsafe { core::mem::transmute(ptr) };
        (code)(0 /* dummy value */, ZERO_PAGE_START);
    }
}

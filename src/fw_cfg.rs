use x86_64::instructions::port::Port;

use crate::{
    loader::{self, Kernel},
    mem::MemoryRegion,
    paging,
};
use sha2::Digest;
use sha2::Sha256;

const DEBUG_PORT: u16 = 0x80;
const FW_CFG_REG: u16 = 0x81;
const FW_CFG_DATA_BASE: u64 = 0x200000;
const FW_CFG_DATA_SIZE: u64 = 0x1000000;
const FW_ADDR: u64 = 0x100000;

// Debug codes
const COPY_START: u8 = 0x50;
const COPY_END: u8 = 0x51;
const HASH_START: u8 = 0x60;
const HASH_END: u8 = 0x61;
const INITRD_COPY_START: u8 = 0x52;
const INITRD_COPY_END: u8 = 0x53;
const INITRD_HASH_START: u8 = 0x62;
const INITRD_HASH_END: u8 = 0x63;

//load the kernel at 2mib in encrypted memory
const KERNEL_LOAD: u64 = 0x200000;
//Firecracker puts kernel at 32mib
pub const KERNEL_ADDR: u64 = 0x2000000;

enum KernelType {
    BzImage,
}

enum Error {
    HashMismatch,
}

pub(crate) struct FwCfg {
    kernel_type: KernelType,
    _cmd_reg: Port<u32>,
    _bounce_buffer: MemoryRegion,
    num_hashes: u64,
    kernel_hash: MemoryRegion,
    initrd_hash: MemoryRegion,
}

impl FwCfg {
    pub fn new() -> Self {
        let _cmd_reg = Port::<u32>::new(FW_CFG_REG);
        let _bounce_buffer = MemoryRegion::new(FW_CFG_DATA_BASE, FW_CFG_DATA_SIZE);
        let base = FW_ADDR - loader::HASH_SIZE_BYTES;
        let kernel_hash = MemoryRegion::new(base, loader::HASH_SIZE_BYTES);
        let initrd_hash = MemoryRegion::new(base - loader::HASH_SIZE_BYTES, loader::HASH_SIZE_BYTES);
        //bzImage default
        let mut fw_cfg = FwCfg {
            kernel_type: KernelType::BzImage,
            _cmd_reg,
            _bounce_buffer,
            num_hashes: 1,
            kernel_hash,
            initrd_hash,
        };

        fw_cfg.init();

        fw_cfg
    }

    fn init(&mut self) {
        self.kernel_type = self.get_kernel_type();

        self.num_hashes = match self.kernel_type {
            KernelType::BzImage => 1,
        };
    }

    fn get_kernel_type(&mut self) -> KernelType {
        KernelType::BzImage
    }

    pub fn load_kernel(
        &mut self,
        kernel_len: u32,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
    ) -> Result<(), &'static str> {
        match self.kernel_type {
            KernelType::BzImage => self.load_bzimage(
                kernel_len,
                initrd_plain_text_addr,
                initrd_load_addr,
                initrd_len,
            )?,
        };
        Ok(())
    }

    //this will copy initrd from plain text to encrypted memory
    pub fn load_initrd(
        &mut self,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
    ) -> Result<(), &'static str> {
        let mut plain_text_region = MemoryRegion::new(initrd_plain_text_addr, initrd_len);
        let mut encrypted_region = MemoryRegion::new(initrd_load_addr, initrd_len);

        Self::debug_write(INITRD_COPY_START);
        encrypted_region
            .as_bytes()
            .copy_from_slice(&plain_text_region.as_bytes());
        Self::debug_write(INITRD_COPY_END);

        Self::debug_write(INITRD_HASH_START);
        let mut hasher = Sha256::new();
        hasher.update(encrypted_region.as_bytes());
        let hash = hasher.finalize();

        Self::validate_hash(&hash, &self.initrd_hash.as_bytes())
            .map_err(|_| "Failed to validate initrd hash")?;
        Self::debug_write(INITRD_HASH_END);

        Ok(())
    }

    pub fn load_bzimage(
        &mut self,
        kernel_len: u32,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
    ) -> Result<(), &'static str> {
        let bzimage_len = kernel_len as u64;

        let mut kernel_region = MemoryRegion::new(KERNEL_ADDR, bzimage_len.into());
        let mut load_region = MemoryRegion::new(KERNEL_LOAD, bzimage_len.into());

        //copy kernel from plain text to encrypted (C-bit and pvalidated) memory
        Self::debug_write(COPY_START);
        load_region
            .as_bytes()
            .copy_from_slice(&kernel_region.as_bytes());
        Self::debug_write(COPY_END);

        Self::debug_write(HASH_START);
        let mut hasher = Sha256::new();
        hasher.update(load_region.as_bytes());
        let hash = hasher.finalize();
        Self::validate_hash(&hash, &self.kernel_hash.as_bytes())
            .map_err(|_| "bzImage verification failed")?;
        Self::debug_write(HASH_END);

        let mut kernel = Kernel::new();

        kernel
            .load_bzimage_from_payload(&mut load_region, initrd_load_addr as u32, initrd_len as u32)
            .unwrap();

        if initrd_len > 0 {
            self.load_initrd(initrd_plain_text_addr, initrd_load_addr, initrd_len)?;
        }

        //set the C-bit everywhere
        paging::setup(false, 0, 0);

        kernel.boot();

        Ok(())
    }

    fn debug_write(val: u8) {
        let mut debug_port = Port::<u8>::new(DEBUG_PORT);
        unsafe { debug_port.write(val) }
    }

    fn validate_hash(new_hash: &[u8], old_hash: &[u8]) -> Result<(), Error> {
        for i in 0..loader::HASH_SIZE_BYTES as usize {
            if new_hash[i] != old_hash[i] {
                return Err(Error::HashMismatch);
            }
        }
        Ok(())
    }
}

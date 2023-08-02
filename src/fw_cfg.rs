use x86_64::instructions::port::Port;

use crate::{
    elf,
    ghcb::{self, Ghcb},
    loader::{self, Kernel},
    mem::MemoryRegion,
    paging,
};
use sha2::Digest;
use sha2::Sha256;

const DEBUG_PORT: u16 = 0x80;
const FW_CFG_REG: u16 = 0x81;
const FW_CFG_DATA_BASE: u64 = 0x1000000 - 0x200000;
const FW_CFG_DATA_SIZE: u64 = 0x200000;
const FW_ADDR: u64 = 0x100000;

// Debug codes
const COPY_START: u8 = 0x50;
const COPY_END: u8 = 0x51;
const HASH_START: u8 = 0x60;
const HASH_END: u8 = 0x61;

//Firecracker puts kernel at 32mib
pub const KERNEL_ADDR: u64 = 0x1000000 - 0x200000;

enum Command {
    ///Get the type of kernel to load, should be the first command issued
    KernelType,
    ///For a direct boot, send the ELF header
    ElfHdr,
    ///For a direct boot, get the next phdr
    PhdrData,
    ///Start reading loadable segment data
    SegData,
}

enum KernelType {
    BzImage,
    Elf,
}

enum Error {
    HashMismatch,
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            Self::KernelType => 0,
            Self::ElfHdr => 3,
            Self::PhdrData => 4,
            Self::SegData => 5,
        }
    }
}

pub(crate) struct FwCfg {
    kernel_type: KernelType,
    cmd_reg: Port<u8>,
    bounce_buffer: MemoryRegion,
    num_hashes: u64,
    hashes: MemoryRegion,
}

impl FwCfg {
    pub fn new() -> Self {
        let cmd_reg = Port::<u8>::new(FW_CFG_REG);
        let bounce_buffer = MemoryRegion::new(FW_CFG_DATA_BASE, FW_CFG_DATA_SIZE);
        let base = FW_ADDR - loader::HASH_SIZE_BYTES;
        let hashes = MemoryRegion::new(base, loader::HASH_SIZE_BYTES);

        //bzImage default
        let mut fw_cfg = FwCfg {
            kernel_type: KernelType::BzImage,
            cmd_reg,
            bounce_buffer,
            num_hashes: 1,
            hashes,
        };

        fw_cfg.init();

        fw_cfg
    }

    fn init(&mut self) {
        self.kernel_type = self.get_kernel_type();

        let base = FW_ADDR - (loader::HASH_SIZE_BYTES * self.num_hashes);
        self.hashes = MemoryRegion::new(base, loader::HASH_SIZE_BYTES * self.num_hashes);
    }

    fn get_kernel_type(&mut self) -> KernelType {
        match self.do_command(Command::KernelType) {
            0 => KernelType::BzImage,
            1 => KernelType::Elf,
            _ => panic!("Invalid kernel type"),
        }
    }

    pub fn load_kernel(
        &mut self,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
    ) -> Result<(), &'static str> {
        match self.kernel_type {
            KernelType::BzImage => self.load_bzimage()?,
            KernelType::Elf => {
                self.load_kernel_elf(initrd_plain_text_addr, initrd_load_addr, initrd_len)?
            }
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

        encrypted_region
            .as_bytes()
            .copy_from_slice(&plain_text_region.as_bytes());

        Self::debug_write(HASH_START);
        let mut hasher = Sha256::new();
        hasher.update(encrypted_region.as_bytes());
        let _hash = hasher.finalize();
        Self::debug_write(HASH_END);

        Ok(())
    }

    pub fn load_bzimage(&mut self) -> Result<(), &'static str> {
        panic!("BzImage not supported!");
    }

    pub fn load_kernel_elf(
        &mut self,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
    ) -> Result<(), &'static str> {
        let mut hasher = Sha256::new();
        //Get elf header
        self.do_command(Command::ElfHdr);

        //Where the elf header will end up on the stack
        let mut header = [0u8; core::mem::size_of::<elf::Elf64_Ehdr>()];

        //Copy elf header from bounce buffer to encrypted region on stack
        Self::debug_write(COPY_START);
        header.copy_from_slice(
            &self.bounce_buffer.as_bytes()[0..core::mem::size_of::<elf::Elf64_Ehdr>()],
        );
        Self::debug_write(COPY_END);

        //Hash elf header in encrypted memory
        Self::debug_write(HASH_START);
        hasher.update(&header);
        Self::debug_write(HASH_END);

        let ehdr = elf::Elf64_Ehdr::from_slice(&header);
        //Stack is in c bit mem so this is fine
        let mut phdrs = [0u8; core::mem::size_of::<elf::Elf64_Phdr>() * 64];

        let mut offset = 0;
        let phdr_sz = core::mem::size_of::<elf::elf64_phdr>();
        //Read all the program headers
        for _i in 0..ehdr.e_phnum {
            //Get next phdr
            self.do_command(Command::PhdrData);
            //Copy phdr from bounce buffer to where we're storing them on the stack
            Self::debug_write(COPY_START);
            phdrs[offset..offset + phdr_sz]
                .copy_from_slice(&self.bounce_buffer.as_bytes()[0..phdr_sz]);
            Self::debug_write(COPY_END);

            //Hash phdr in encrypted mem
            Self::debug_write(HASH_START);
            hasher.update(&phdrs[offset..offset + phdr_sz]);
            Self::debug_write(HASH_END);

            offset += phdr_sz;
        }

        //Copy and hash loadable segments
        let mut phdr_offset = 0;
        for _i in 0..ehdr.e_phnum {
            //initialize phdr array in encrypted memory
            let phdr = elf::Elf64_Phdr::from_slice(&phdrs[phdr_offset..phdr_offset + phdr_sz]);

            //Skip the program headers that don't correspond to loadable segments
            if phdr.p_type & elf::PT_LOAD == 0 || phdr.p_filesz == 0 {
                continue;
            }

            let mut num_left = phdr.p_filesz;
            let load_addr = phdr.p_paddr;
            //memory region for where the segment will be loaded
            let mut seg = MemoryRegion::new(load_addr, num_left);

            let mut seg_offset = 0;
            //Tell hypervisor to serve first segment
            self.do_command(Command::SegData);
            loop {
                let mut read_num = FW_CFG_DATA_SIZE;
                if num_left < read_num {
                    read_num = num_left;
                }
                //alias for bounce buffer region
                let src = &self.bounce_buffer.as_bytes()[0..read_num as usize];

                //Copy portion of segment from bounce buffer to encrypted region
                Self::debug_write(COPY_START);
                seg.as_bytes()[seg_offset..seg_offset + read_num as usize].copy_from_slice(&src);
                Self::debug_write(COPY_END);

                //Hash what we just copied in encrypted memory
                Self::debug_write(HASH_START);
                hasher.update(&seg.as_bytes()[seg_offset..seg_offset + read_num as usize]);
                Self::debug_write(HASH_END);

                num_left -= read_num;
                if num_left == 0 {
                    break;
                } else {
                    seg_offset += read_num as usize;
                    //Tell hypervisor to serve next segment
                    self.do_command(Command::SegData);
                }
            }
            phdr_offset += phdr_sz;
        }
        Self::debug_write(HASH_START);
        let seg_hash = hasher.finalize();
        Self::debug_write(HASH_END);

        //Verify segments hash
        Self::validate_hash(&seg_hash, &self.hashes.as_bytes())
            .map_err(|_| "vmlinux verification failed")?;

        Self::debug_write(0x90);

        //Write bootparams
        let mut kernel_params = Kernel::new();
        kernel_params.entry_point = ehdr.e_entry;

        self.load_initrd(initrd_plain_text_addr, initrd_load_addr, initrd_len)?;

        //set the C-bit everywhere
        paging::setup(false, 0, 0);

        kernel_params.boot();

        Ok(())
    }

    fn do_command(&mut self, cmd: Command) -> u8 {
        unsafe { self.cmd_reg.write(cmd.into()) };
        let mut val = unsafe { self.cmd_reg.read() };
        unsafe {
            if ghcb::SEV_ES {
                val = Ghcb::get_val() as u8;
            }
        }
        val
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

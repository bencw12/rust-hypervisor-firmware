use core::panic;

use sha2::Sha256;
use x86_64::{instructions::port::Port, PhysAddr};

use crate::{mem::MemoryRegion, loader::{self, Kernel}, elf, pvh, paging, boot::Info};

use sha2::Digest;

const DEBUG_PORT: u16 = 0x80;
const FW_CFG_REG: u16 = 0x81;
const FW_CFG_DATA_BASE: u64 = 0x200000;
const FW_CFG_DATA_SIZE: u64 = 0x200000;
const FW_ADDR: u64 = 0x100000;

// Debug codes
const COPY_START: u8 = 0x50;
const COPY_END: u8 = 0x51;
const HASH_START: u8 = 0x60;
const HASH_END: u8 = 0x61;

enum Command {
    ///Get the type of kernel to load, should be the first command issued
    KernelType,
    ///Get the length of the bzImage
    BzImageLen,
    ///Start reading the bzImage in chunks
    BzimageData,
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
    HashMismatch
}

impl Into<u32> for Command {
    fn into(self) -> u32 {
        match self {
            Self::KernelType => 0,
            Self::BzImageLen => 1,
            Self::BzimageData => 2,
            Self::ElfHdr => 3,
            Self::PhdrData => 4,
            Self::SegData => 5,
        }
    }
}

pub(crate) struct FwCfg {
    kernel_type: KernelType,
    cmd_reg: Port<u32>,
    bounce_buffer: MemoryRegion,
    num_hashes: u64,
    hashes: MemoryRegion,
    hasher: Sha256,
}

impl FwCfg {
    pub fn new() -> Self {
        let cmd_reg = Port::<u32>::new(FW_CFG_REG);
        let bounce_buffer = MemoryRegion::new(FW_CFG_DATA_BASE, FW_CFG_DATA_SIZE);
        let base = FW_ADDR - loader::HASH_SIZE_BYTES;
        let hashes = MemoryRegion::new(base, loader::HASH_SIZE_BYTES);
        let hasher = Sha256::new();
        //Clear C bit on bounce buffer region
        paging::set_or_clear_enc_bit(
            PhysAddr::new(FW_CFG_DATA_BASE), 
            FW_CFG_DATA_SIZE, 
            true, 
            crate::paging::EncBitMode::Clear
        );

        //bzImage default
        let mut fw_cfg = FwCfg {
            kernel_type: KernelType::BzImage,
            cmd_reg,
            bounce_buffer,
            num_hashes: 1,
            hashes,
            hasher,
        };

        fw_cfg.init();

        fw_cfg
    }

    fn init(&mut self) {
        self.kernel_type = self.get_kernel_type();

        self.num_hashes = match self.kernel_type {
            KernelType::BzImage => 1,
            KernelType::Elf => 3,
        };

        let base = FW_ADDR - (loader::HASH_SIZE_BYTES * self.num_hashes);
        self.hashes = MemoryRegion::new(base, loader::HASH_SIZE_BYTES * self.num_hashes); 
    }

    fn get_kernel_type(&mut self) -> KernelType {
        match self.do_command(Command::KernelType) {
            0 => KernelType::BzImage,
            1 => KernelType::Elf,
            _ => panic!("Invalid kernel type")
        }
    }

    pub fn load_kernel(&mut self, info: &pvh::StartInfo) -> Result<(), &'static str> {
        match self.kernel_type {
            KernelType::BzImage => self.load_bzimage(info)?,
            KernelType::Elf => self.load_kernel_elf(info)?,
        };

        Ok(())
    }
    
    fn load_kernel_elf(&mut self, info: &pvh::StartInfo) -> Result<(), &'static str> {
        let mut debug_port = Port::<u8>::new(DEBUG_PORT);
        //Get elf header
        self.do_command(Command::ElfHdr);

        //Where the elf header will end up on the stack
        let mut header = [0u8; core::mem::size_of::<elf::Elf64_Ehdr>()]; 

        //Copy elf header from bounce buffer to encrypted region on stack
        Self::debug_write(&mut debug_port, COPY_START);
        header.copy_from_slice(&self.bounce_buffer.as_bytes()[0..core::mem::size_of::<elf::Elf64_Ehdr>()]);
        Self::debug_write(&mut debug_port, COPY_END);

        //Hash elf header in encrypted memory
        Self::debug_write(&mut debug_port, HASH_START);
        self.hasher.update(&header);
        let elf_hdr_hash = self.hasher.finalize_reset();
        Self::debug_write(&mut debug_port, HASH_END);

        let mut hashes_offset = 0;
        //Verify elf header hash
        Self::validate_hash(
            &elf_hdr_hash, 
            &self.hashes.as_bytes()[hashes_offset..hashes_offset+loader::HASH_SIZE_BYTES as usize]
        ).map_err(|_| "Elf header verification failed")?;

        log!("ELF header verification succeeded");
        hashes_offset += loader::HASH_SIZE_BYTES as usize;

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
            Self::debug_write(&mut debug_port, COPY_START);
            phdrs[offset..offset+phdr_sz].copy_from_slice(
                &self.bounce_buffer.as_bytes()[0..phdr_sz]
            );
            Self::debug_write(&mut debug_port, COPY_END);

            //Hash phdr in encrypted mem
            Self::debug_write(&mut debug_port, HASH_START);
            self.hasher.update(&phdrs[offset..offset+phdr_sz]);
            Self::debug_write(&mut debug_port, HASH_END);

            offset += phdr_sz;
        }
        //hash program headers
        Self::debug_write(&mut debug_port, HASH_START);
        let phdr_hash = self.hasher.finalize_reset();
        Self::debug_write(&mut debug_port, HASH_END);

        //Verify phdrs hash
        Self::validate_hash(
            &phdr_hash, 
            &self.hashes.as_bytes()[hashes_offset..hashes_offset+loader::HASH_SIZE_BYTES as usize]
        ).map_err(|_| "Program header verification failed")?;

        log!("Program header verification succeeded");
        //update hash offset to segments hash location
        hashes_offset += loader::HASH_SIZE_BYTES as usize;

        //Copy and hash loadable segments
        let mut phdr_offset = 0;
        for _i in 0..ehdr.e_phnum {
            //initialize phdr array in encrypted memory
            let phdr = elf::Elf64_Phdr::from_slice(
                &phdrs[phdr_offset..phdr_offset+phdr_sz]
            );

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
                Self::debug_write(&mut debug_port, COPY_START);
                seg.as_bytes()[seg_offset..seg_offset+read_num as usize].copy_from_slice(&src);
                Self::debug_write(&mut debug_port, COPY_END);

                //Hash what we just copied in encrypted memory
                Self::debug_write(&mut debug_port, HASH_START);
                self.hasher.update(&seg.as_bytes()[seg_offset..seg_offset + read_num as usize]);
                Self::debug_write(&mut debug_port, HASH_END);

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
        Self::debug_write(&mut debug_port, HASH_START);
        let seg_hash = self.hasher.finalize_reset();
        Self::debug_write(&mut debug_port, HASH_END);

        //Verify segments hash
        Self::validate_hash(
            &seg_hash, 
            &self.hashes.as_bytes()[hashes_offset..hashes_offset+loader::HASH_SIZE_BYTES as usize]
        ).map_err(|_| "Program header verification failed")?;

        log!("Loadable segment hash verification succeeded");

        
        //Write bootparams
        log!("Booting kernel");
        let mut kernel_params = Kernel::new(info);
        kernel_params.entry_point = ehdr.e_entry;

        kernel_params.params.hdr.type_of_loader = loader::KERNEL_LOADER_OTHER;
        kernel_params.params.hdr.boot_flag = loader::KERNEL_BOOT_FLAG_MAGIC;
        kernel_params.params.hdr.header = loader::KERNEL_HDR_MAGIC;
        kernel_params.params.hdr.cmd_line_ptr = loader::CMDLINE_START as u32;
        kernel_params.params.hdr.cmdline_size = loader::CMDLINE_MAX_LEN as u32;
        kernel_params.params.hdr.kernel_alignment = loader::KERNEL_MIN_ALIGNMENT_BYTES;

        kernel_params.add_e820_entry(
            0, loader::EBDA_START, loader::E820_RAM
        ).unwrap();

        paging::set_or_clear_enc_bit(
            PhysAddr::new(FW_CFG_DATA_BASE), 
            FW_CFG_DATA_SIZE, 
            true, 
            paging::EncBitMode::Set
        );


        kernel_params.write_params();

        kernel_params.append_cmdline(info.cmdline());
        //Re-encrypt the bounce buffer region
        kernel_params.boot();

        Ok(())
    }
    
    fn load_bzimage(&mut self, info: &pvh::StartInfo) -> Result<(), &'static str> {
        //Load bzImage
        let mut debug_port = Port::<u8>::new(DEBUG_PORT);
        let bzimage_len = self.do_command(Command::BzImageLen);
        //copy the bzimage to encrypted memory after bounce buffer region
        const KERNEL_LOAD: u64 = FW_CFG_DATA_BASE + FW_CFG_DATA_SIZE;
        let mut kernel_region = MemoryRegion::new(KERNEL_LOAD, bzimage_len.into());
        let mut offset = 0;
        let mut num_left = bzimage_len as u64;
        loop {
            self.do_command(Command::BzimageData);

            let mut read_num = FW_CFG_DATA_SIZE;
            if num_left < read_num {
                read_num = num_left;
            }

            Self::debug_write(&mut debug_port, COPY_START);
            kernel_region.as_bytes()[offset..offset+read_num as usize].copy_from_slice(
                &self.bounce_buffer.as_bytes()[..read_num as usize]
            );
            Self::debug_write(&mut debug_port, COPY_END);

            num_left -= read_num;
            offset += read_num as usize;

            if num_left == 0 {
                break;
            }
        }

        paging::set_or_clear_enc_bit(
            PhysAddr::new(FW_CFG_DATA_BASE), 
            FW_CFG_DATA_SIZE, 
            true, 
            paging::EncBitMode::Set
        );

        let mut hasher = Sha256::new();
        Self::debug_write(&mut debug_port, HASH_START);
        hasher.update(kernel_region.as_bytes());
        let hash = hasher.finalize();
        Self::debug_write(&mut debug_port, HASH_END);

        Self::validate_hash(
            &hash, 
            &self.hashes.as_bytes()
        ).map_err(|_| "bzImage verification failed")?;
        log!("BzImage verification succeeded");

        let mut kernel = Kernel::new(info);
        // let mut port = Port::new(0x80);

        // unsafe { port.write(0x35u8)};
        kernel.load_bzimage_from_payload(&mut kernel_region).unwrap();
        // unsafe { port.write(0x36u8)};

        kernel.append_cmdline(info.cmdline());
        kernel.boot();

        Ok(())
    }

    fn do_command(&mut self, cmd: Command) -> u32 {
        unsafe { self.cmd_reg.write(cmd.into()) }
        unsafe { self.cmd_reg.read() }
    }

    fn debug_write(debug_reg: &mut Port<u8>, val: u8) {
        unsafe { debug_reg.write(val)}
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



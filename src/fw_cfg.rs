use sha2::Sha256;
use x86_64::instructions::port::Port;

use crate::{
    loader::{self, Kernel},
    mem::MemoryRegion,
};

use sha2::Digest;

// const DEBUG_PORT: u16 = 0x80;
const FW_CFG_REG: u16 = 0x81;
const FW_CFG_DATA_BASE: u64 = 0x200000;
const FW_CFG_DATA_SIZE: u64 = 0x1000000;
const FW_ADDR: u64 = 0x100000;

// Debug codes
// const COPY_START: u8 = 0x50;
// const COPY_END: u8 = 0x51;
// const HASH_START: u8 = 0x60;
// const HASH_END: u8 = 0x61;

#[no_mangle]
static mut BZIMAGE_LEN: [u64; 1] = [0];

// enum Command {
//     ///Get the type of kernel to load, should be the first command issued
//     KernelType,
//     ///Get the length of the bzImage
//     BzImageLen,
//     ///Start reading the bzImage in chunks
//     BzimageData,
//     ///For a direct boot, send the ELF header
//     ElfHdr,
//     ///For a direct boot, get the next phdr
//     PhdrData,
//     Start reading loadable segment data
//     SegData,
// }

enum KernelType {
    BzImage,
    //Elf,
}

// enum Error {
//     HashMismatch,
// }

// impl Into<u32> for Command {
//     fn into(self) -> u32 {
//         match self {
//             Self::KernelType => 0,
//             Self::BzImageLen => 1,
//             Self::BzimageData => 2,
//             Self::ElfHdr => 3,
//             Self::PhdrData => 4,
//             //Self::SegData => 5,
//         }
//     }
// }

pub(crate) struct FwCfg {
    kernel_type: KernelType,
    _cmd_reg: Port<u32>,
    _bounce_buffer: MemoryRegion,
    num_hashes: u64,
    hashes: MemoryRegion,
    _hasher: Sha256,
}

impl FwCfg {
    pub fn new() -> Self {
        let _cmd_reg = Port::<u32>::new(FW_CFG_REG);
        let _bounce_buffer = MemoryRegion::new(FW_CFG_DATA_BASE, FW_CFG_DATA_SIZE);
        let base = FW_ADDR - loader::HASH_SIZE_BYTES;
        let hashes = MemoryRegion::new(base, loader::HASH_SIZE_BYTES);
        let _hasher = Sha256::new();
        //Clear C bit on bounce buffer region
        //let mut debug_port = Port::<u8>::new(DEBUG_PORT);
        //unsafe { debug_port.write(0x10u8) };
        // paging::set_or_clear_enc_bit(
        //     PhysAddr::new(FW_CFG_DATA_BASE),
        //     FW_CFG_DATA_SIZE,
        //     true,
        //     crate::paging::EncBitMode::Clear,
        // );
        // unsafe { debug_port.write(0x11u8) };

        //bzImage default
        let mut fw_cfg = FwCfg {
            kernel_type: KernelType::BzImage,
            _cmd_reg,
            _bounce_buffer,
            num_hashes: 1,
            hashes,
            _hasher,
        };

        fw_cfg.init();

        fw_cfg
    }

    fn init(&mut self) {
        self.kernel_type = self.get_kernel_type();

        self.num_hashes = match self.kernel_type {
            KernelType::BzImage => 1,
            //KernelType::Elf => 3,
        };

        let base = FW_ADDR - (loader::HASH_SIZE_BYTES * self.num_hashes);
        self.hashes = MemoryRegion::new(base, loader::HASH_SIZE_BYTES * self.num_hashes);
    }

    fn get_kernel_type(&mut self) -> KernelType {
        // match self.do_command(Command::KernelType) {
        //     0 => KernelType::BzImage,
        //     1 => KernelType::Elf,
        //     _ => panic!("Invalid kernel type"),
        // }
        KernelType::BzImage
    }

    pub fn load_kernel(&mut self) -> Result<(), &'static str> {
        match self.kernel_type {
            KernelType::BzImage => self.load_bzimage()?,
            //KernelType::Elf => self.load_kernel_elf()?,
        };

        Ok(())
    }

    // fn load_kernel_elf(&mut self) -> Result<(), &'static str> {
    //     // let mut debug_port = Port::<u8>::new(DEBUG_PORT);
    //     //Get elf header
    //     self.do_command(Command::ElfHdr);

    //     //Where the elf header will end up on the stack
    //     let mut header = [0u8; core::mem::size_of::<elf::Elf64_Ehdr>()];

    //     //Copy elf header from bounce buffer to encrypted region on stack
    //     // Self::debug_write(&mut debug_port, COPY_START);
    //     header.copy_from_slice(
    //         &self.bounce_buffer.as_bytes()[0..core::mem::size_of::<elf::Elf64_Ehdr>()],
    //     );
    //     // Self::debug_write(&mut debug_port, COPY_END);

    //     //Hash elf header in encrypted memory
    //     // Self::debug_write(&mut debug_port, HASH_START);
    //     // self.hasher.update(&header);
    //     // let elf_hdr_hash = self.hasher.finalize_reset();
    //     // Self::debug_write(&mut debug_port, HASH_END);

    //     // let mut hashes_offset = 0;
    //     //Verify elf header hash
    //     // Self::validate_hash(
    //     //     &elf_hdr_hash,
    //     //     &self.hashes.as_bytes()
    //     //         [hashes_offset..hashes_offset + loader::HASH_SIZE_BYTES as usize],
    //     // )
    //     // .map_err(|_| "Elf header verification failed")?;

    //     #[cfg(debug_assertions)]
    //     log!("ELF header verification succeeded");
    //     // hashes_offset += loader::HASH_SIZE_BYTES as usize;

    //     let ehdr = elf::Elf64_Ehdr::from_slice(&header);
    //     //Stack is in c bit mem so this is fine
    //     let mut phdrs = [0u8; core::mem::size_of::<elf::Elf64_Phdr>() * 64];

    //     let mut offset = 0;
    //     let phdr_sz = core::mem::size_of::<elf::elf64_phdr>();
    //     //Read all the program headers
    //     for _i in 0..ehdr.e_phnum {
    //         //Get next phdr
    //         // self.do_command(Command::PhdrData);
    //         //Copy phdr from bounce buffer to where we're storing them on the stack
    //         // Self::debug_write(&mut debug_port, COPY_START);
    //         phdrs[offset..offset + phdr_sz]
    //             .copy_from_slice(&self.bounce_buffer.as_bytes()[0..phdr_sz]);
    //         // Self::debug_write(&mut debug_port, COPY_END);

    //         //Hash phdr in encrypted mem
    //         // Self::debug_write(&mut debug_port, HASH_START);
    //         // self.hasher.update(&phdrs[offset..offset + phdr_sz]);
    //         // Self::debug_write(&mut debug_port, HASH_END);

    //         offset += phdr_sz;
    //     }
    //     //hash program headers
    //     // Self::debug_write(&mut debug_port, HASH_START);
    //     // let phdr_hash = self.hasher.finalize_reset();
    //     // Self::debug_write(&mut debug_port, HASH_END);

    //     //Verify phdrs hash
    //     // Self::validate_hash(
    //     //     &phdr_hash,
    //     //     &self.hashes.as_bytes()
    //     //         [hashes_offset..hashes_offset + loader::HASH_SIZE_BYTES as usize],
    //     // )
    //     // .map_err(|_| "Program header verification failed")?;

    //     #[cfg(debug_assertions)]
    //     log!("Program header verification succeeded");
    //     //update hash offset to segments hash location
    //     // hashes_offset += loader::HASH_SIZE_BYTES as usize;

    //     //Copy and hash loadable segments
    //     let mut phdr_offset = 0;
    //     for _i in 0..ehdr.e_phnum {
    //         //initialize phdr array in encrypted memory
    //         let phdr = elf::Elf64_Phdr::from_slice(&phdrs[phdr_offset..phdr_offset + phdr_sz]);

    //         //Skip the program headers that don't correspond to loadable segments
    //         if phdr.p_type & elf::PT_LOAD == 0 || phdr.p_filesz == 0 {
    //             continue;
    //         }

    //         let mut num_left = phdr.p_filesz;
    //         let load_addr = phdr.p_paddr;
    //         //memory region for where the segment will be loaded
    //         let mut seg = MemoryRegion::new(load_addr, num_left);

    //         let mut seg_offset = 0;
    //         //Tell hypervisor to serve first segment
    //         // self.do_command(Command::SegData);
    //         loop {
    //             let mut read_num = FW_CFG_DATA_SIZE;
    //             if num_left < read_num {
    //                 read_num = num_left;
    //             }
    //             //alias for bounce buffer region
    //             let src = &self.bounce_buffer.as_bytes()[0..read_num as usize];

    //             //Copy portion of segment from bounce buffer to encrypted region
    //             // Self::debug_write(&mut debug_port, COPY_START);
    //             seg.as_bytes()[seg_offset..seg_offset + read_num as usize].copy_from_slice(&src);
    //             // Self::debug_write(&mut debug_port, COPY_END);

    //             //Hash what we just copied in encrypted memory
    //             // Self::debug_write(&mut debug_port, HASH_START);
    //             // self.hasher
    //             //     .update(&seg.as_bytes()[seg_offset..seg_offset + read_num as usize]);
    //             // Self::debug_write(&mut debug_port, HASH_END);

    //             num_left -= read_num;
    //             if num_left == 0 {
    //                 break;
    //             } else {
    //                 seg_offset += read_num as usize;
    //                 //Tell hypervisor to serve next segment
    //                 // self.do_command(Command::SegData);
    //             }
    //         }
    //         phdr_offset += phdr_sz;
    //     }
    //     // Self::debug_write(&mut debug_port, HASH_START);
    //     // let seg_hash = self.hasher.finalize_reset();
    //     // Self::debug_write(&mut debug_port, HASH_END);

    //     //Verify segments hash
    //     // Self::validate_hash(
    //     //     &seg_hash,
    //     //     &self.hashes.as_bytes()
    //     //         [hashes_offset..hashes_offset + loader::HASH_SIZE_BYTES as usize],
    //     //  )
    //     // .map_err(|_| "Program header verification failed")?;

    //     #[cfg(debug_assertions)]
    //     log!("Loadable segment hash verification succeeded");

    //     //Write bootparams
    //     #[cfg(debug_assertions)]
    //     log!("Booting kernel");
    //     let mut kernel_params = Kernel::new();
    //     kernel_params.entry_point = ehdr.e_entry;

    //     //Re-encrypt the bounce buffer region
    //     // paging::set_or_clear_enc_bit(
    //     //     PhysAddr::new(FW_CFG_DATA_BASE),
    //     //     FW_CFG_DATA_SIZE,
    //     //     true,
    //     //     paging::EncBitMode::Set,
    //     // );
    //     kernel_params.boot();

    //     Ok(())
    // }

    pub fn load_bzimage(&mut self) -> Result<(), &'static str> {
        //Load bzImage
        // let mut debug_port = Port::<u8>::new(DEBUG_PORT);
        // unsafe { debug_port.write(0x60u8) };
        let bzimage_len = unsafe { BZIMAGE_LEN[0] };
        //let bzimage_len = self.do_command(Command::BzImageLen);
        //copy the bzimage to encrypted memory after bounce buffer region
        //load the kernel at 2mib
        const KERNEL_LOAD: u64 = 0x200000;
        //hypervisor puts kernel at 16mib
        const KERNEL_ADDR: u64 = 0x1000000;
        let mut kernel_region = MemoryRegion::new(KERNEL_ADDR, bzimage_len.into());

        //log!("TEST, 0x{:x}", bzimage_len);
        // Self::debug_write(&mut debug_port, 0x61);

        //copy bzimage from plain text to encrypted memory
        // kernel_region
        //     .as_bytes()
        //     .copy_from_slice(&self.bounce_buffer.as_bytes()[..bzimage_len as usize]);
        //set the C bit on bounce buffer again
        // paging::set_or_clear_enc_bit(
        //     PhysAddr::new(FW_CFG_DATA_BASE),
        //     FW_CFG_DATA_SIZE,
        //     true,
        //     paging::EncBitMode::Set,
        // );

        let mut load_region = MemoryRegion::new(KERNEL_LOAD, bzimage_len.into());

        //copy kernel from kernel_addr to kernel_load
        load_region
            .as_bytes()
            .copy_from_slice(&kernel_region.as_bytes());
        //unsafe { debug_port.write(0x36u8) };

        //let mut hasher = Sha256::new();

        // Self::debug_write(&mut debug_port, HASH_START);
        //hasher.update(load_region.as_bytes());

        //let hash = hasher.finalize();
        //log!("TEST");
        //Self::debug_write(&mut debug_port, HASH_END);

        //Self::validate_hash(&hash, &self.hashes.as_bytes())
        //    .map_err(|_| "bzImage verification failed")?;
        //#[cfg(debug_assertions)]
        //log!("BzImage verification succeeded");

        let mut kernel = Kernel::new();

        kernel
            .load_bzimage_from_payload(&mut kernel_region)
            .unwrap();

        kernel.boot();

        Ok(())
    }

    // fn do_command(&mut self, cmd: Command) -> u32 {
    //     unsafe { self.cmd_reg.write(cmd.into()) }
    //     unsafe { self.cmd_reg.read() }
    // }

    // fn debug_write(debug_reg: &mut Port<u8>, val: u8) {
    //     unsafe { debug_reg.write(val) }
    // }

    // fn validate_hash(new_hash: &[u8], old_hash: &[u8]) -> Result<(), Error> {
    //     for i in 0..loader::HASH_SIZE_BYTES as usize {
    //         if new_hash[i] != old_hash[i] {
    //             return Err(Error::HashMismatch);
    //         }
    //     }
    //     Ok(())
    // }
}

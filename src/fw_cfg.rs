use x86_64::{
    instructions::port::Port,
    structures::paging::{PageSize, Size2MiB},
};

use crate::{
    boot::{BootE820Entry, CCBlob, Header, SetupData, SETUP_CC_BLOB},
    elf,
    ghcb::{self, Ghcb},
    loader::{
        self, Kernel, CPUID_PAGE_ADDR, CPUID_PAGE_LEN, SECRETS_PAGE_ADDR, SECRETS_PAGE_LEN,
        ZERO_PAGE_START,
    },
    mem::MemoryRegion,
    paging,
};
use sha2::Digest;
use sha2::Sha256;

//load the kernel at 2mib in encrypted memory
//Firecracker puts kernel at 32mib
pub const KERNEL_ADDR: u64 = 0x1000000 - 0x200000;
//Max bzImage length (16MiB)

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
        initrd_size_aligned: u64,
    ) -> Result<(), &'static str> {
        match self.kernel_type {
            KernelType::BzImage => self.load_bzimage()?,
            KernelType::Elf => self.load_kernel_elf(
                initrd_plain_text_addr,
                initrd_load_addr,
                initrd_len,
                initrd_size_aligned,
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
        panic!("Not supported!");
    }

    pub fn load_kernel_elf(
        &mut self,
        initrd_plain_text_addr: u64,
        initrd_load_addr: u64,
        initrd_len: u64,
        initrd_size_aligned: u64,
    ) -> Result<(), &'static str> {
        let mut hasher = Sha256::new();
        //Get elf header
        self.do_command(Command::ElfHdr);

        let mut header_region = MemoryRegion::new(
            ZERO_PAGE_START + 0x1f1,
            core::mem::size_of::<Header>().try_into().unwrap(),
        );
        let bootparams_header =
            unsafe { core::mem::transmute::<_, &mut Header>(header_region.as_bytes().as_ptr()) };

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
        // let elf_hdr_hash = hasher.finalize_reset();
        Self::debug_write(HASH_END);

        // let mut hashes_offset = 0;
        //Verify elf header hash
        // Self::validate_hash(
        //     &elf_hdr_hash,
        //     &self.hashes.as_bytes()[hashes_offset..hashes_offset+loader::HASH_SIZE_BYTES as usize]
        // ).map_err(|_| "Elf header verification failed")?;

        // hashes_offset += loader::HASH_SIZE_BYTES as usize;

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
        //hash program headers
        // Self::debug_write(HASH_START);
        // let phdr_hash = hasher.finalize_reset();
        // Self::debug_write(HASH_END);

        //Verify phdrs hash
        // Self::validate_hash(
        //     &phdr_hash,
        //     &self.hashes.as_bytes()[hashes_offset..hashes_offset+loader::HASH_SIZE_BYTES as usize]
        // ).map_err(|_| "Program header verification failed")?;

        #[cfg(debug_assertions)]
        log!("Program header verification succeeded");
        //update hash offset to segments hash location
        // hashes_offset += loader::HASH_SIZE_BYTES as usize;

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

            // log!("seg addr=0x{:x}, size=0x{:x}", load_addr, num_left);

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

        bootparams_header.ramdisk_image = initrd_load_addr as u32;
        bootparams_header.ramdisk_size = initrd_len as u32;

        if bootparams_header.setup_data == 0 {
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
            bootparams_header.setup_data = setup_data_addr as u64;
        }

        self.load_initrd(initrd_plain_text_addr, initrd_load_addr, initrd_len)?;

        // //set the plain text region for the kernel and the ghcb page private
        ghcb::page_state_change(KERNEL_ADDR, Size2MiB::SIZE, true);

        // //set plain text region for initrd private
        ghcb::page_state_change(initrd_plain_text_addr, initrd_size_aligned, true);

        //set the C-bit everywhere
        paging::setup(false, 0, 0);

        //re-validate the region we used for the plain text kernel
        // let entry = boot_e820_entry {
        //     addr: KERNEL_ADDR,
        //     size: Size2MiB::SIZE,
        //     type_: 1,
        // };
        // paging::pvalidate_ram(&entry, 0 as u64, 0, 0, false);

        //re-validate the region we used for the plain text initrd
        let entry = BootE820Entry {
            addr: initrd_plain_text_addr,
            size: initrd_size_aligned,
            type_: 1,
        };
        paging::pvalidate_ram(&entry, 0 as u64, 0, 0, false);

        kernel_params.boot();

        Ok(())
    }

    fn do_command(&mut self, cmd: Command) -> u8 {
        unsafe { self.cmd_reg.write(cmd.into()) };
        unsafe { self.cmd_reg.read() };

        let val = Ghcb::get_val() as u8;

        // Self::debug_write(val as u8);

        // let mut debug_port = Port::<u8>::new(DEBUG_PORT);
        // unsafe { debug_port.write(val) }

        val
        // Self::debug_write(val);
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

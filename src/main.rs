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

#![feature(alloc_error_handler)]
#![feature(stmt_expr_attributes)]
#![no_std]
#![no_main]
#![cfg_attr(not(feature = "log-serial"), allow(unused_variables, unused_imports))]
#![feature(abi_x86_interrupt)]
use core::panic::PanicInfo;
use x86_64::{
    instructions::{hlt, interrupts, port::Port},
    registers::{
        control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
        xcontrol::{XCr0, XCr0Flags},
    },
    structures::paging::{PageSize, Size2MiB},
};

#[macro_use]
mod serial;

#[macro_use]
mod asm;
mod boot;
mod elf;
mod fw_cfg;
mod gdt;
mod ghcb;
mod idt;
mod loader;
mod mem;
mod paging;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    #[cfg(debug_assertions)]
    log!("PANIC: {}", _info);
    loop {
        hlt()
    }
}

// Enable SSE2 for XMM registers (needed for EFI calling)
fn enable_sse() {
    let mut cr0 = Cr0::read();
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
    cr0.remove(Cr0Flags::TASK_SWITCHED);
    cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
    cr0.insert(Cr0Flags::EXTENSION_TYPE);
    cr0.insert(Cr0Flags::ALIGNMENT_MASK);
    cr0.insert(Cr0Flags::WRITE_PROTECT);
    unsafe { Cr0::write(cr0) };
    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::OSFXSR);
    cr4.insert(Cr4Flags::OSXSAVE);
    cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
    unsafe { Cr4::write(cr4) };

    //enable AVX for sha2 crate
    let mut xcro0 = XCr0::read();
    xcro0.insert(XCr0Flags::SSE);
    xcro0.insert(XCr0Flags::AVX);
    xcro0.insert(XCr0Flags::X87);
    unsafe { XCr0::write(xcro0) };
}

#[no_mangle]
pub extern "C" fn rust64_start() {
    main()
}

fn main() -> ! {
    let initrd_len;
    let initrd_load_addr: u64;
    //Firecracker stashes memory size and initrd_len in r14 and r15 respectively
    unsafe { core::arch::asm!("", out("r14") initrd_len) };
    unsafe { core::arch::asm!("", out("r15") initrd_load_addr) };

    //this aligns the stack
    unsafe { core::arch::asm!("push rax") };

    enable_sse();

    interrupts::enable();
    idt::init_idt();

    let align_to_pagesize = |address| address & !(0x200000 - 1);
    //plain text inird will be just before its final resting place
    let initrd_load_addr_aligned = align_to_pagesize(initrd_load_addr);
    let initrd_plain_text_addr = align_to_pagesize(initrd_load_addr_aligned - initrd_len);
    //initrd_plain_text_addr should already be 2mb aligned
    let initrd_size_aligned = if (initrd_len & !Size2MiB::SIZE) != 0 {
        (initrd_len & !(Size2MiB::SIZE - 1)) + Size2MiB::SIZE
    } else {
        initrd_len
    };

    //set up paging so we can have encrypted memory
    paging::setup(true, initrd_plain_text_addr, initrd_size_aligned);

    //set up ghcb so we can do writes to ports
    ghcb::register_ghcb_page();

    //signal firmware start, although a bit late this is the earliest we can do it
    let mut debug_port = Port::<u8>::new(0x80);
    unsafe {
        //This also sets ghcb::SEV_ES to true because we wouldn't invoke the #VC handler if we weren't SEV-ES
        debug_port.write(0x31u8);
    };

    let mut loader = fw_cfg::FwCfg::new();
    unsafe {
        debug_port.write(0x31u8);
    };

    loader
        .load_kernel(initrd_plain_text_addr, initrd_load_addr, initrd_len)
        .unwrap();

    panic!("Shouldn't reach here")
}

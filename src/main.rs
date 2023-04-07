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
};

#[macro_use]
#[cfg(debug_assertions)]
mod serial;

#[macro_use]
mod asm;
mod boot;
// mod elf;
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
    //this aligns the stack
    unsafe { core::arch::asm!("push rax") };

    interrupts::enable();

    idt::init_idt();
    //initialize logger
    #[cfg(debug_assertions)]
    serial::PORT.borrow_mut().init();
    //set control registers
    enable_sse();
    //enable paging/SEV
    paging::setup();

    let mut debug_port = Port::<u8>::new(0x80);
    //We have to wait for paging to be set up and for the GHCB page
    //to be registered before we do PIO, so this timestamp is a little late but
    //signals the start of the guest firmware
    unsafe { debug_port.write(0x31u8) };
    let mut loader = fw_cfg::FwCfg::new();
    loader.load_kernel().unwrap();

    panic!("Shouldn't reach here")
}

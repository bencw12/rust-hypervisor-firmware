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
#![cfg_attr(test, allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "log-serial"), allow(unused_variables, unused_imports))]

use core::panic::PanicInfo;

use crate::{boot::Info, mem::MemoryRegion, paging::set_or_clear_enc_bit};
use sha2::Sha256;
use digest::Digest;
use loader::Kernel;
use x86_64::{instructions::hlt, PhysAddr, registers::{control::{ Cr4, Cr4Flags, Cr0, Cr0Flags}, xcontrol::{XCr0, XCr0Flags}}};
use x86_64::instructions::port::Port;
#[macro_use]
mod serial;

#[macro_use]
mod common;
mod asm;
mod boot;
mod loader;
mod gdt;
mod mem;
mod paging;
mod pvh;
mod elf;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    loop {
        hlt()
    }
}

// Enable SSE2 for XMM registers (needed for EFI calling)
fn enable_sse() {
    let mut cr0 = Cr0::read();
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
    cr0.remove(Cr0Flags::TASK_SWITCHED);
    cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
    cr0.insert(Cr0Flags::EXTENSION_TYPE);
    cr0.insert(Cr0Flags::ALIGNMENT_MASK);
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

fn load_kernel(info: &mut pvh::StartInfo) {
    let mut kernel = Kernel::new(info);
    //For now putting kernel length in info.pad
    let mut kernel_file = MemoryRegion::new(loader::KERNEL_LOCATION, info._pad as u64);

    set_or_clear_enc_bit(
        PhysAddr::new(loader::KERNEL_LOCATION),
        info._pad as u64,
        true,
        paging::EncBitMode::Clear,
    );

    let mut port = Port::new(0x80);

    unsafe { port.write(0x35u8)};

    let mut hasher = Sha256::new();
    hasher.update(kernel_file.as_bytes());
    let hash = hasher.finalize();

    unsafe { port.write(0x36u8)};

    log!("hash: {:02x?}", hash);

    //Try to load elf if bzimage magic is not present
    match kernel.load_bzimage_from_payload(&mut kernel_file) {
        Err(loader::Error::MagicMissing) => kernel.load_elf_from_payload(&mut kernel_file).unwrap(),
        _ => ()
    };

    kernel.append_cmdline(info.cmdline());
    set_or_clear_enc_bit(
        PhysAddr::new(loader::KERNEL_LOCATION),
        info._pad as u64,
        true,
        paging::EncBitMode::Set,
    );
    log!("Jumping to kernel");
    kernel.boot();
}

#[no_mangle]
pub extern "C" fn rust64_start(rdi: &mut pvh::StartInfo) -> ! {
    main(rdi)
}

fn main(info: &mut pvh::StartInfo) -> ! {
    //align stack
    unsafe{core::arch::asm!("push rax")};
    //initialize logger
    serial::PORT.borrow_mut().init();
    //set control registers
    enable_sse();
    //enable paging/SEV
    paging::setup();
    load_kernel(info);
    panic!("Shouldn't reach here")
}

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
use bzimage::Kernel;
use x86_64::{instructions::hlt, PhysAddr};

#[macro_use]
mod serial;

#[macro_use]
mod common;

mod asm;
mod boot;
mod bzimage;
mod gdt;
mod mem;
mod paging;
mod pci;
mod pvh;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    loop {
        hlt()
    }
}

fn load_bzimage(info: &mut pvh::StartInfo) {
    let mut kernel = Kernel::new(info);
    //For now putting kernel length in info.pad
    let mut kernel_file = MemoryRegion::new(bzimage::KERNEL_LOCATION, info._pad as u64);
    set_or_clear_enc_bit(
        PhysAddr::new(bzimage::KERNEL_LOCATION),
        info._pad as u64,
        true,
        paging::EncBitMode::Clear,
    );
    kernel.load_kernel_from_payload(&mut kernel_file).unwrap();
    kernel.append_cmdline(info.cmdline());
    set_or_clear_enc_bit(
        PhysAddr::new(bzimage::KERNEL_LOCATION),
        info._pad as u64,
        true,
        paging::EncBitMode::Set,
    );
    log!("Jumping to kernel");
    kernel.boot();
}

#[no_mangle]
pub extern "C" fn rust64_start(rdi: &mut pvh::StartInfo) -> ! {
    serial::PORT.borrow_mut().init();
    paging::setup();

    main(rdi)
}

fn main(info: &mut pvh::StartInfo) -> ! {
    pci::print_bus();
    load_bzimage(info);
    panic!("Shouldn't reach here")
}

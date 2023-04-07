use crate::ghcb::Ghcb;
use core::arch::asm;
use x86_64::instructions::hlt;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

extern "x86-interrupt" fn vmm_comm_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    x86_64::instructions::interrupts::disable();

    let val: u8;
    let port: u16;
    //get value writing to port
    unsafe { asm!("", out("al") val) };
    //get port we're writing to
    unsafe { asm!("", out("dx") port) };

    if error_code != 0x7b {
        loop {
            hlt();
        }
    }

    Ghcb::port_io(port, val);

    //vmgexit
    unsafe {
        asm!("rep; vmmcall\n\r");
    }

    x86_64::instructions::interrupts::enable();

    let ret_addr = stack_frame.instruction_pointer.0 + 1;
    //This is a weird workaround but it works
    let ptr = ret_addr as *const ();
    let code: extern "C" fn() = unsafe { core::mem::transmute(ptr) };
    (code)();
}

pub fn init_idt() {
    unsafe {
        IDT.vmm_communication_exception
            .set_handler_fn(vmm_comm_handler);
        IDT.load();
    };
}

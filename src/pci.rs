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

use atomic_refcell::AtomicRefCell;
use x86_64::instructions::port::{PortReadOnly, PortWriteOnly};

const MAX_DEVICES: u8 = 32;
const MAX_FUNCTIONS: u8 = 8;

const INVALID_VENDOR_ID: u16 = 0xffff;

static PCI_CONFIG: AtomicRefCell<PciConfig> = AtomicRefCell::new(PciConfig::new());

struct PciConfig {
    address_port: PortWriteOnly<u32>,
    data_port: PortReadOnly<u32>,
}

impl PciConfig {
    const fn new() -> Self {
        // We use the legacy, port-based Configuration Access Mechanism (CAM).
        Self {
            address_port: PortWriteOnly::new(0xcf8),
            data_port: PortReadOnly::new(0xcfc),
        }
    }

    fn read(&mut self, bus: u8, device: u8, func: u8, offset: u8) -> u32 {
        assert_eq!(offset % 4, 0);
        assert!(device < MAX_DEVICES);
        assert!(func < MAX_FUNCTIONS);

        let addr = u32::from(bus) << 16; // bus bits 23-16
        let addr = addr | u32::from(device) << 11; // slot/device bits 15-11
        let addr = addr | u32::from(func) << 8; // function bits 10-8
        let addr = addr | u32::from(offset & 0xfc); // register 7-0
        let addr = addr | 1u32 << 31; // enable bit 31

        // SAFETY: We have exclusive access to the ports, so the data read will
        // correspond to the address written.
        unsafe {
            self.address_port.write(addr);
            self.data_port.read()
        }
    }
}

fn get_device_details(bus: u8, device: u8, func: u8) -> (u16, u16) {
    let data = PCI_CONFIG.borrow_mut().read(bus, device, func, 0);
    ((data & 0xffff) as u16, (data >> 16) as u16)
}

pub fn print_bus() {
    for device in 0..MAX_DEVICES {
        let (vendor_id, device_id) = get_device_details(0, device, 0);
        if vendor_id == INVALID_VENDOR_ID {
            continue;
        }
        log!(
            "Found PCI device vendor={:x} device={:x} in slot={}",
            vendor_id,
            device_id,
            device
        );
    }
}

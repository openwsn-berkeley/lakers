use crate::*;

/// structs compatible with the C FFI
#[repr(C)]
pub struct EdhocInitiatorWaitM2C {
    pub state: WaitM2, // opaque state
}

#[derive(Clone, Debug)]
#[repr(C)]
pub struct EADItemC {
    pub label: u8,
    pub is_critical: bool,
    pub value: *mut EdhocMessageBuffer,
}

impl EADItemC {
    pub fn to_rust(&self) -> EADItem {
        let value = if self.value.is_null() {
            None
        } else {
            Some(unsafe { *self.value })
        };

        EADItem {
            label: self.label,
            is_critical: self.is_critical,
            value,
        }
    }
}

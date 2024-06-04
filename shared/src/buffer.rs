pub const MAX_EDHOC_MESSAGE_SIZE_LEN: usize = 128 + 64;
pub const MAX_EAD_SIZE_LEN: usize = 64;
pub const MAX_SUITES_LEN: usize = 9;

#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum EdhocBufferError {
    BufferAlreadyFull,
    SliceTooLong,
}

/// A fixed-size (but parameterized) buffer for EDHOC messages.
// TODO: replace EdhocMessageBuffer with EdhocBuffer
// NOTE: how can this const generic thing work across the C and Python bindings?
#[repr(C)]
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EdhocBuffer<const N: usize> {
    pub content: [u8; N],
    pub len: usize,
}

impl<const N: usize> Default for EdhocBuffer<N> {
    fn default() -> Self {
        EdhocBuffer {
            content: [0; N],
            len: 0,
        }
    }
}

impl<const N: usize> EdhocBuffer<N> {
    pub const fn new() -> Self {
        EdhocBuffer {
            content: [0u8; N],
            len: 0,
        }
    }

    pub fn new_from_slice(slice: &[u8]) -> Result<Self, EdhocBufferError> {
        let mut buffer = Self::new();
        if buffer.fill_with_slice(slice).is_ok() {
            Ok(buffer)
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }

    pub fn get(self, index: usize) -> Option<u8> {
        self.content.get(index).copied()
    }

    pub fn contains(&self, item: &u8) -> bool {
        self.content.contains(item)
    }

    pub fn push(&mut self, item: u8) -> Result<(), EdhocBufferError> {
        if self.len < self.content.len() {
            self.content[self.len] = item;
            self.len += 1;
            Ok(())
        } else {
            Err(EdhocBufferError::BufferAlreadyFull)
        }
    }

    pub fn get_slice(&self, start: usize, len: usize) -> Option<&[u8]> {
        self.content.get(start..start + len)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.content[0..self.len]
    }

    pub fn fill_with_slice(&mut self, slice: &[u8]) -> Result<(), EdhocBufferError> {
        if slice.len() <= self.content.len() {
            self.len = slice.len();
            self.content[..self.len].copy_from_slice(slice);
            Ok(())
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }

    pub fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), EdhocBufferError> {
        if self.len + slice.len() <= self.content.len() {
            self.content[self.len..self.len + slice.len()].copy_from_slice(slice);
            self.len += slice.len();
            Ok(())
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }
}

mod test {
    use super::*;

    #[test]
    fn test_edhoc_buffer() {
        let mut buffer = EdhocBuffer::<5>::new();
        assert_eq!(buffer.len, 0);
        assert_eq!(buffer.content, [0; 5]);

        buffer.push(1).unwrap();
        assert_eq!(buffer.len, 1);
        assert_eq!(buffer.content, [1, 0, 0, 0, 0]);
    }

    #[test]
    fn test_new_from_slice() {
        let buffer = EdhocBuffer::<5>::new_from_slice(&[1, 2, 3]).unwrap();
        assert_eq!(buffer.len, 3);
        assert_eq!(buffer.content, [1, 2, 3, 0, 0]);
    }
}

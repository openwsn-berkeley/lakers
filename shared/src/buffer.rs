use core::ops::Index;

// NOTE: This constant is only here for now because it is only ever used in instances of EdhocBuffer.
// TODO: move to lib.rs, once EdhocMessageBuffer is replaced by EdhocBuffer.
pub const MAX_SUITES_LEN: usize = 9;

#[derive(PartialEq, Debug)]
#[repr(C)]
pub enum EdhocBufferError {
    BufferAlreadyFull,
    SliceTooLong,
}

/// A fixed-size (but parameterized) buffer for EDHOC messages.
///
/// Trying to have an API as similar as possible to `heapless::Vec`,
/// so that in the future it can be hot-swappable by the application.
// NOTE: how would this const generic thing work across the C and Python bindings?
#[derive(PartialEq, Debug, Copy, Clone)]
#[repr(C)]
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

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn capacity(&self) -> usize {
        N
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
        if index < self.len {
            None
        } else {
            self.content.get(index).copied()
        }
    }

    pub fn contains(&self, item: &u8) -> bool {
        self.as_slice().contains(item)
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
        if start.saturating_add(len) > self.len {
            None
        } else {
            self.content.get(start..start + len)
        }
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

    // so far only used in test contexts
    pub fn from_hex(hex: &str) -> Self {
        let mut buffer = EdhocBuffer::new();
        buffer.len = hex.len() / 2;
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let chunk_str = core::str::from_utf8(chunk).unwrap();
            buffer.content[i] = u8::from_str_radix(chunk_str, 16).unwrap();
        }
        buffer
    }

    pub fn building() -> BufferBuilder<typenum::U0, N> {
        BufferBuilder {
            buf: Self::new(),
            phantom: core::marker::PhantomData,
        }
    }
}

impl<const N: usize> Index<usize> for EdhocBuffer<N> {
    type Output = u8;
    #[track_caller]
    fn index(&self, item: usize) -> &Self::Output {
        &self.as_slice()[item]
    }
}

impl<const N: usize> TryInto<EdhocBuffer<N>> for &[u8] {
    type Error = ();

    fn try_into(self) -> Result<EdhocBuffer<N>, Self::Error> {
        let mut buffer = [0u8; N];
        if self.len() <= buffer.len() {
            buffer[..self.len()].copy_from_slice(self);

            Ok(EdhocBuffer {
                content: buffer,
                len: self.len(),
            })
        } else {
            Err(())
        }
    }
}

/// A nascent [`EdhocBuffer`] with a guaranteed `BuiltLength` prefix that can be assembled with its
/// methods in a type-checked non-panicking way.
pub struct BufferBuilder<Used: typenum::Unsigned, const N: usize> {
    buf: EdhocBuffer<N>,
    phantom: core::marker::PhantomData<Used>,
}

impl<Used: typenum::Unsigned, const N: usize> BufferBuilder<Used, N>
where
    Used: core::ops::Add<typenum::U1>,
    <Used as core::ops::Add<typenum::U1>>::Output: typenum::Unsigned,
{
    pub fn push(
        mut self,
        data: u8,
    ) -> BufferBuilder<<Used as core::ops::Add<typenum::U1>>::Output, N> {
        self.buf.push(data).unwrap();
        BufferBuilder {
            buf: self.buf,
            phantom: core::marker::PhantomData,
        }
    }

    pub fn extend_from_array<const D: usize>(
        mut self,
        data: &[u8; D],
    ) -> BufferBuilder<
        <Used as core::ops::Add<
            <typenum::Const<D> as typenum::generic_const_mappings::ToUInt>::Output,
        >>::Output,
        N,
    >
    where
        typenum::Const<D>: typenum::generic_const_mappings::ToUInt,
        Used:
            core::ops::Add<<typenum::Const<D> as typenum::generic_const_mappings::ToUInt>::Output>,
        <Used as core::ops::Add<
            <typenum::Const<D> as typenum::generic_const_mappings::ToUInt>::Output,
        >>::Output: typenum::Unsigned,
    {
        self.buf.extend_from_slice(data.as_slice()).unwrap();
        BufferBuilder {
            buf: self.buf,
            phantom: core::marker::PhantomData,
        }
    }

    pub fn extend_from_buffer<const D: usize>(
        mut self,
        data: &EdhocBuffer<D>,
    ) -> BufferBuilder<
        <Used as core::ops::Add<
            <typenum::Const<D> as typenum::generic_const_mappings::ToUInt>::Output,
        >>::Output,
        N,
    >
    where
        typenum::Const<D>: typenum::generic_const_mappings::ToUInt,
        Used:
            core::ops::Add<<typenum::Const<D> as typenum::generic_const_mappings::ToUInt>::Output>,
        <Used as core::ops::Add<
            <typenum::Const<D> as typenum::generic_const_mappings::ToUInt>::Output,
        >>::Output: typenum::Unsigned,
    {
        self.buf.extend_from_slice(data.as_slice()).unwrap();
        BufferBuilder {
            buf: self.buf,
            phantom: core::marker::PhantomData,
        }
    }

    pub fn done(self) -> EdhocBuffer<N> {
        const {
            assert!(Used::USIZE <= N, "Built data exceeds buffer size");
        }
        self.buf
    }
}

mod test {

    #[test]
    fn test_edhoc_buffer() {
        let mut buffer = crate::EdhocBuffer::<5>::new();
        assert_eq!(buffer.len, 0);
        assert_eq!(buffer.content, [0; 5]);

        buffer.push(1).unwrap();
        assert_eq!(buffer.len, 1);
        assert_eq!(buffer.content, [1, 0, 0, 0, 0]);
    }

    #[test]
    fn test_new_from_slice() {
        let buffer = crate::EdhocBuffer::<5>::new_from_slice(&[1, 2, 3]).unwrap();
        assert_eq!(buffer.len, 3);
        assert_eq!(buffer.content, [1, 2, 3, 0, 0]);
    }
}

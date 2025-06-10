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
#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
// `#[hax_lib::attributes]` is not usable here due to https://github.com/cryspen/hax/issues/899
pub struct EdhocBuffer<const N: usize> {
    #[deprecated]
    pub content: [u8; N],
    #[deprecated(note = "use .len()")]
    // `#[hax_lib::refine(len <= N)]` would allow dropping all the other hax_lib requires lines on
    // functions.
    pub len: usize,
}

#[allow(deprecated)]
impl<const N: usize> Default for EdhocBuffer<N> {
    fn default() -> Self {
        EdhocBuffer {
            content: [0; N],
            len: 0,
        }
    }
}

#[allow(deprecated)]
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

    pub const fn new_from_slice(slice: &[u8]) -> Result<Self, EdhocBufferError> {
        let mut buffer = Self::new();
        if buffer.fill_with_slice(slice).is_ok() {
            Ok(buffer)
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }

    /// Creates a new buffer from an array, with compile-time checking of the size.
    ///
    /// This is identical to [`.new_from_slice`][Self::new_from_slice], but handles overflow as a
    /// built-time error, thus removing the need for a fallible result.
    ///
    /// This is particularly useful in tests and other const contexts:
    ///
    /// ```
    /// # use lakers_shared::*;
    /// const MY_CONST: EdhocMessageBuffer = EdhocMessageBuffer::new_from_array(&[0, 1, 2]);
    /// ```
    ///
    /// While this fails to build:
    ///
    /// ```compile_fail
    /// # use lakers_shared::*;
    /// const MY_CONST: EdhocMessageBuffer = EdhocMessageBuffer::new_from_array(&[0; 10_000]);
    /// ```
    pub const fn new_from_array<const AN: usize>(input: &[u8; AN]) -> Self {
        const /* BUT NOT FOR HAX */ {
            if AN > N {
                panic!("Array exceeds buffer size")
            }
        };
        match Self::new_from_slice(input.as_slice()) {
            Ok(s) => s,
            _ => panic!("unreachable: Was checked above in a guaranteed-const fashion"),
        }
    }

    pub fn contains(&self, item: &u8) -> bool {
        self.as_slice().contains(item)
    }

    #[inline]
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
        // The strict criterion avoids the need to use checked / saturating addition, which is not
        // present in hax for usize.
        if start >= usize::MAX / 2 || len >= usize::MAX / 2 {
            return None;
        }
        if self.len > N {
            // Just needed for hax typechecking, does not know this invariant and needs returning
            // None as a non-panicking exit.
            return None;
        }
        let end = start + len;
        if end > self.len {
            None
        } else {
            Some(&self.content[start..end])
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        if self.len > N {
            // Just needed for hax typechecking, does not know this invariant and needs returning
            // None as a non-panicking exit.
            return &[];
        }
        &self.content[0..self.len]
    }

    pub const fn fill_with_slice(&mut self, slice: &[u8]) -> Result<(), EdhocBufferError> {
        if slice.len() <= self.content.len() {
            self.len = slice.len();
            // Could be content[..len].copy_from_silce() if not for const, and
            // self.content.split_at_mut(self.len).0.copy_from_slice() if not for hax.
            let mut i = 0;
            while i < self.len {
                self.content[i] = slice[i];
                i = i + 1;
            }
            Ok(())
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }

    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), EdhocBufferError> {
        // The strict criterion avoids the need to use checked / saturating addition, which is not
        // present in hax for usize.
        if self.len >= usize::MAX / 2 || slice.len() >= usize::MAX / 2 {
            return Err(EdhocBufferError::SliceTooLong);
        }
        let end = self.len() + slice.len();
        if end <= self.content.len() {
            self.content[self.len..end].copy_from_slice(slice);
            self.len += slice.len();
            Ok(())
        } else {
            Err(EdhocBufferError::SliceTooLong)
        }
    }

    /// Like [`.extend_from_slice()`], but leaves the data in the buffer "uninitialized" --
    /// anticipating that the user will populate `self.content[result]`.
    ///
    /// ("Uninitialized" is in quotes because there are no guarentees on the content; from the
    /// compiler's perspective, that area is initialized because this type doesn't play with
    /// [`MaybeUninit`][core::mem::MaybeUninit], but don't rely on it).
    ///
    /// This is not a fully idiomatic Rust API: Preferably, this would return a `&mut [u8]` of the
    /// requested length. However, as `.as_mut_slice()` or `.get_mut()` can not be checked by hax,
    /// pushing and getting a range is the next best thing.
    pub fn extend_reserve(
        &mut self,
        length: usize,
    ) -> Result<core::ops::Range<usize>, EdhocBufferError> {
        // The strict criterion avoids the need to use checked / saturating addition, which is not
        // present in hax for usize.
        if self.len >= usize::MAX / 2 || length >= usize::MAX / 2 {
            return Err(EdhocBufferError::SliceTooLong);
        }
        let start = self.len;
        let end = start + length;
        if end <= N {
            self.len = end;
            Ok(start..end)
        } else {
            Err(EdhocBufferError::BufferAlreadyFull)
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
}

#[allow(deprecated)]
impl<const N: usize> Index<usize> for EdhocBuffer<N> {
    type Output = u8;
    #[track_caller]
    fn index(&self, item: usize) -> &Self::Output {
        &self.as_slice()[item]
    }
}

#[allow(deprecated)]
impl<const N: usize> TryFrom<&[u8]> for EdhocBuffer<N> {
    type Error = ();

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let mut buffer = [0u8; N];
        if input.len() <= buffer.len() {
            buffer[..input.len()].copy_from_slice(input);

            Ok(EdhocBuffer {
                content: buffer,
                len: input.len(),
            })
        } else {
            Err(())
        }
    }
}

#[allow(deprecated)]
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

use crate::padding::errors::PaddingError;

/// What fills the padding bytes before the final length byte in ANSI X9.23.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fill {
    /// Zero bytes, which are checked when the padding is removed.
    Zeros,
    /// Random bytes, which can't be checked, so only the length byte is validated.
    Random
}

/// A padding scheme. Every scheme ends with a byte holding the padding length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    /// PKCS#7 (RFC 5652 section 6.3): every padding byte holds the padding length.
    /// Works with block sizes from 1 to 255 bytes.
    Pkcs7,
    /// PKCS#5 (RFC 8018 section 6.1.1): the same bytes as PKCS#7, for 8-byte blocks only.
    Pkcs5,
    /// ANSI X9.23: the padding bytes are set by [`Fill`], then a final length byte.
    AnsiX923(Fill)
}

impl Padding {
    /// Rejects block sizes the padding length can't describe or the scheme doesn't allow.
    fn check_block_size(&self, block_size: usize) -> Result<(), PaddingError> {
        if block_size == 0 || block_size > 255 {
            return Err(PaddingError::InvalidBlockSize(block_size))
        }
        if matches!(self, Padding::Pkcs5) && block_size != 8 {
            return Err(PaddingError::Pkcs5RequiresBlock8(block_size));
        }
        Ok(())
    }

    /// Builds the final block from the leftover `tail`, for data processed in chunks.
    ///
    /// `out.len()` is the block size. If the data was already block-aligned, pass an
    /// empty `tail` to get a full block of padding.
    ///
    /// # Errors
    ///
    /// - [`PaddingError::InvalidBlockSize`] if `out` is empty or longer than 255 bytes.
    /// - [`PaddingError::Pkcs5RequiresBlock8`] for PKCS#5 if `out` isn't 8 bytes long.
    /// - [`PaddingError::InvalidLength`] if `tail` isn't shorter than `out`.
    /// - [`PaddingError::Rng`] if random fill can't be generated.
    ///
    /// # Examples
    ///
    /// ```
    /// use oes::padding::Padding;
    ///
    /// let mut block = [0u8; 8];
    /// Padding::Pkcs7.pad_final(&[1, 2, 3], &mut block).unwrap();
    /// assert_eq!(block, [1, 2, 3, 5, 5, 5, 5, 5]);
    ///
    /// assert_eq!(Padding::Pkcs7.unpad_block(&block), Ok(3));
    /// ```
    pub fn pad_final(&self, tail: &[u8], out: &mut [u8]) -> Result<(), PaddingError> {
        let block_size = out.len();
        self.check_block_size(block_size)?;
        if tail.len() >= block_size {
            return Err(PaddingError::InvalidLength { len: tail.len(), block_size })
        }

        let n = block_size - tail.len(); // 1..=block_size
        out[..tail.len()].copy_from_slice(tail);

        let fill = &mut out[tail.len()..];
        match self {
            Padding::Pkcs7 | Padding::Pkcs5 => fill.fill(n as u8),
            Padding::AnsiX923(f) => {
                let (body, last) = fill.split_at_mut(fill.len() - 1);
                match f {
                    Fill::Zeros => body.fill(0),
                    Fill::Random => getrandom::getrandom(body).map_err(|_| PaddingError::Rng)?
                }
                last[0] = n as u8;
            }
        }
        Ok(())
    }

    /// Returns how many bytes at the start of the final `block` are data, not padding.
    ///
    /// `block.len()` is the block size. Every byte is examined, with no early exit at
    /// the first wrong one.
    ///
    /// # Errors
    ///
    /// - [`PaddingError::InvalidBlockSize`] if `block` is empty or longer than 255 bytes.
    /// - [`PaddingError::Pkcs5RequiresBlock8`] for PKCS#5 if `block` isn't 8 bytes long.
    /// - [`PaddingError::Invalid`] if the padding is wrong.
    pub fn unpad_block(&self, block: &[u8]) -> Result<usize, PaddingError> {
        let block_size = block.len();
        self.check_block_size(block_size)?;

        let n = block[block_size - 1] as usize;
        let mut bad = (n == 0) | (n > block_size);
        let pad_len = n.min(block_size);

        // Check every byte without early exit
        for (i, &b) in block.iter().enumerate() {
            let in_pad = i >= block_size - pad_len;
            let expected = match self {
                Padding::Pkcs7 | Padding::Pkcs5 => n as u8,
                Padding::AnsiX923(Fill::Zeros) => { if i == block_size - 1 { n as u8 } else { 0 }
                },
                Padding::AnsiX923(Fill::Random) => b,
            };
            bad |= in_pad & (b != expected);
        }

        if bad { Err(PaddingError::Invalid) } else { Ok(block_size - n) }
    }

    /// Appends padding to `data` so its length becomes a multiple of `block_size`.
    ///
    /// Always adds at least one byte. On error, `data` is left unchanged.
    ///
    /// # Errors
    ///
    /// - [`PaddingError::InvalidBlockSize`] if `block_size` is 0 or above 255.
    /// - [`PaddingError::Pkcs5RequiresBlock8`] for PKCS#5 if `block_size` isn't 8.
    /// - [`PaddingError::Rng`] if random fill can't be generated.
    ///
    /// # Examples
    ///
    /// ```
    /// use oes::padding::{Fill, Padding};
    ///
    /// let padding = Padding::AnsiX923(Fill::Zeros);
    /// let mut data = vec![1, 2, 3];
    ///
    /// padding.pad(&mut data, 8).unwrap();
    /// assert_eq!(data, [1, 2, 3, 0, 0, 0, 0, 5]);
    ///
    /// let keep = padding.unpad_len(&data, 8).unwrap();
    /// assert_eq!(&data[..keep], [1, 2, 3]);
    /// ```
    pub fn pad(&self, data: &mut Vec<u8>, block_size: usize) -> Result<(), PaddingError> {
        self.check_block_size(block_size)?;
        let tail_len = data.len() % block_size;
        let mut block = vec![0u8; block_size];
        self.pad_final(&data[data.len() - tail_len..], &mut block)?;
        data.truncate(data.len() - tail_len);
        data.extend_from_slice(&block);
        Ok(())
    }

    /// Returns the length of `data` without its padding, leaving `data` unchanged.
    ///
    /// Only the last block is examined.
    ///
    /// # Errors
    ///
    /// - [`PaddingError::InvalidBlockSize`] if `block_size` is 0 or above 255.
    /// - [`PaddingError::Pkcs5RequiresBlock8`] for PKCS#5 if `block_size` isn't 8.
    /// - [`PaddingError::InvalidLength`] if `data` is empty or not a multiple of `block_size`.
    /// - [`PaddingError::Invalid`] if the padding is wrong.
    pub fn unpad_len(&self, data: &[u8], block_size: usize) -> Result<usize, PaddingError> {
        self.check_block_size(block_size)?;
        if data.is_empty() || !data.len().is_multiple_of(block_size) {
            return Err(PaddingError::InvalidLength { len: data.len(), block_size })
        }
        let last = &data[data.len() - block_size..];
        let keep = self.unpad_block(last)?;
        Ok(data.len() - block_size + keep)
    }
}
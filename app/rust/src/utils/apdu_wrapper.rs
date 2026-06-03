use crate::constants::{
    APDU_INDEX_CLA, APDU_INDEX_INS, APDU_INDEX_LEN, APDU_INDEX_P1, APDU_INDEX_P2, APDU_MIN_LENGTH,
};

/// Wraps an apdu_buffer and provides utility methods
pub struct ApduBufferRead<'apdu> {
    inner: &'apdu mut [u8],
    // Number of bytes actually received in the APDU. The backing `inner`
    // buffer can be larger than the APDU (e.g. Ledger's SDK reuses a single
    // buffer for both request and response), so all reads of APDU data must
    // be bounded by `rx` instead of `inner.len()`. `write()` keeps access to
    // the full buffer because responses may legitimately exceed `rx`.
    rx: usize,
}

#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum ApduBufferReadError {
    /// The provided buffer was not long enough
    ///
    /// This happens if the slice is less than it should be for minimum
    /// or if the provided slice is too short for the provided `rx`
    LengthMismatch { expected: usize, got: usize },

    /// The requested payload was too short then expected
    NotEnoughPayload { expected: usize, got: usize },

    /// The provided buffer was too short and didn't have a payload
    NoPayload,
}

impl ApduBufferReadError {
    pub fn length_to_payload(self) -> Self {
        match self {
            Self::LengthMismatch { expected, got } => Self::NotEnoughPayload { expected, got },
            err => err,
        }
    }
}

impl<'apdu> ApduBufferRead<'apdu> {
    fn check_min_len(
        len: usize,
        expected: usize,
        offset: impl Into<Option<usize>>,
    ) -> Result<(), ApduBufferReadError> {
        let offset = offset.into().unwrap_or_default();

        if len - offset < expected {
            Err(ApduBufferReadError::LengthMismatch {
                expected,
                got: len - offset,
            })
        } else {
            Ok(())
        }
    }

    /// Create a new "ApduBuffer" from the given mutable byte slice
    ///
    /// The function checks if there's at least the minimum required number of bytes (APDU_MIN_LENGTH)
    /// and if the byte slice is at least as long as rx
    #[inline(never)]
    pub fn new(buf: &'apdu mut [u8], rx: u32) -> Result<Self, ApduBufferReadError> {
        crate::sys::zemu_log_stack("ApduBufferRead::new\x00");
        //check buf is at least 4
        Self::check_min_len(buf.len(), APDU_MIN_LENGTH as usize, None)?;

        //check rx is at least 4
        Self::check_min_len(rx as usize, APDU_MIN_LENGTH as usize, None)?;

        //check buf is at least rx
        Self::check_min_len(buf.len(), rx as usize, None)?;

        Ok(Self {
            inner: buf,
            rx: rx as usize,
        })
    }

    /// Alias to idx APDU_INDEX_CLA
    pub fn cla(&self) -> u8 {
        self.inner[APDU_INDEX_CLA]
    }

    /// Alias to idx APDU_INDEX_INS
    pub fn ins(&self) -> u8 {
        self.inner[APDU_INDEX_INS]
    }

    /// Alias to idx APDU_INDEX_P1
    pub fn p1(&self) -> u8 {
        self.inner[APDU_INDEX_P1]
    }

    /// Alias to idx APDU_INDEX_P2
    pub fn p2(&self) -> u8 {
        self.inner[APDU_INDEX_P2]
    }

    /// Return the remaining part of the buffer if present
    ///
    /// It's expected the buffer to have the prepended len at idx APDU_INDEX_LEN,
    /// thus the data would start at idx 5 until len - 5.
    ///
    /// The advertised payload length (`Lc`) is validated against `rx`, the
    /// number of bytes actually received, so a host cannot make the reader
    /// hand out stale bytes that live past the end of the received APDU.
    pub fn payload(&self) -> Result<&[u8], ApduBufferReadError> {
        let plen = self.inner[APDU_INDEX_LEN] as usize;
        //check that the received APDU is long enough for the payload
        Self::check_min_len(self.rx, plen, APDU_MIN_LENGTH as usize)
            .map_err(|err| err.length_to_payload())?;

        Ok(&self.inner[APDU_MIN_LENGTH as usize..APDU_MIN_LENGTH as usize + plen])
        //we checked the size beforehand
    }

    /// Discard the structure to obtain the inner slice for writing
    pub fn write(self) -> &'apdu mut [u8] {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: usize = APDU_MIN_LENGTH as usize;

    fn header(lc: u8) -> [u8; MIN] {
        // CLA, INS, P1, P2, Lc
        [0xEE, 0x01, 0x00, 0x00, lc]
    }

    // Exact-fit: the advertised Lc equals rx - APDU_MIN_LENGTH. Payload is
    // returned with the expected length.
    #[test]
    fn payload_bounded_exact_fit() {
        let mut buf = [0u8; 64];
        buf[..MIN].copy_from_slice(&header(3));
        buf[MIN..MIN + 3].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let rx = (MIN + 3) as u32;

        let reader = ApduBufferRead::new(&mut buf, rx).expect("new");
        assert_eq!(reader.payload().unwrap(), &[0xAA, 0xBB, 0xCC]);
    }

    // The backing buffer is larger than rx. An honest APDU with Lc that fits
    // within rx must still parse.
    #[test]
    fn payload_bounded_smaller_rx_ok() {
        let mut buf = [0u8; 260];
        buf[..MIN].copy_from_slice(&header(2));
        buf[MIN..MIN + 2].copy_from_slice(&[0x11, 0x22]);
        // Deliberately dirty the stale tail to catch any over-read.
        for slot in &mut buf[MIN + 2..] {
            *slot = 0xFE;
        }
        let rx = (MIN + 2) as u32;

        let reader = ApduBufferRead::new(&mut buf, rx).expect("new");
        assert_eq!(reader.payload().unwrap(), &[0x11, 0x22]);
    }

    // Host advertises Lc that extends past rx. The reader must reject without
    // handing out any of the stale backing-buffer bytes past position rx.
    #[test]
    fn payload_bounded_rejects_stale_read() {
        let mut buf = [0u8; 260];
        buf[..MIN].copy_from_slice(&header(200));
        for slot in &mut buf[MIN..] {
            *slot = 0xFE;
        }
        // Received APDU is only 5 bytes (header only); Lc = 200 is a lie.
        let rx = MIN as u32;

        let reader = ApduBufferRead::new(&mut buf, rx).expect("new");
        assert!(matches!(
            reader.payload(),
            Err(ApduBufferReadError::NotEnoughPayload { .. })
        ));
    }

    // Host advertises Lc exactly one byte past rx. Must also be rejected.
    #[test]
    fn payload_bounded_rejects_off_by_one() {
        let mut buf = [0u8; 64];
        buf[..MIN].copy_from_slice(&header(4));
        let rx = (MIN + 3) as u32;

        let reader = ApduBufferRead::new(&mut buf, rx).expect("new");
        assert!(matches!(
            reader.payload(),
            Err(ApduBufferReadError::NotEnoughPayload { .. })
        ));
    }

    // Minimum APDU (no Lc data): Lc = 0 is always valid.
    #[test]
    fn payload_bounded_empty_payload() {
        let mut buf = [0u8; 64];
        buf[..MIN].copy_from_slice(&header(0));
        let rx = MIN as u32;

        let reader = ApduBufferRead::new(&mut buf, rx).expect("new");
        assert!(reader.payload().unwrap().is_empty());
    }
}

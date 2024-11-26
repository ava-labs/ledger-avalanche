/*******************************************************************************
*   (c) 2018-2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub enum ConvertError<const R: usize, const S: usize> {
    /// The DER prefix (at index 0) found was different than the expected 0x30
    InvalidDERPrefix(u8),
    /// The R marker was different than expected (0x02)
    InvalidRMarker(u8),
    /// The encoded len for R was not the same as the expected
    InvalidRLen(usize),
    /// The S marker was different than expected (0x02)
    InvalidSMarker(u8),
    /// The encoded len for S was not the same as the expected
    InvalidSLen(usize),
    /// Passed signature was too short to be read properly
    TooShort,
    /// Passed signature encoded payload len was not in the expected range
    InvalidPayloadLen {
        min: usize,
        payload: usize,
        max: usize,
    },
}

#[inline(never)]
/// Converts a DER encoded signature into a RSV encoded signture
pub fn convert_der_to_rs<const R: usize, const S: usize>(
    sig: &[u8],
    out_r: &mut [u8; R],
    out_s: &mut [u8; S],
) -> Result<(usize, usize), ConvertError<R, S>> {
    const MINPAYLOADLEN: usize = 1;
    const MAXPAYLOADLEN: usize = 33;

    let payload_range = core::ops::RangeInclusive::new(MINPAYLOADLEN, MAXPAYLOADLEN);
    // https://github.com/libbitcoin/libbitcoin-system/wiki/ECDSA-and-DER-Signatures#serialised-der-signature-sequence
    // 0                [1 byte]   - DER Prefix (0x30)
    // 1                [1 byte]   - Payload len
    // 2                [1 byte]   - R Marker. Always 02
    // 3                [1 byte]   - R Len                      RLEN
    // ROFFSET ...      [.?. byte] - R                          ROFFSET
    // ROFFSET+RLEN     [1 byte]   - S Marker. Always 02
    // ROFFSET+RLEN+1   [1 byte]   - S Length                   SLEN
    // ROFFSET+RLEN+2   [.?. byte] - S                          SOFFSET

    //check that we have at least the DER prefix and the payload len
    if sig.len() < 2 {
        return Err(ConvertError::TooShort);
    }

    //check DER prefix
    if sig[0] != 0x30 {
        return Err(ConvertError::InvalidDERPrefix(sig[0]));
    }

    //check payload len size
    let payload_len = sig[1] as usize;
    let min_payload_len = 2 + MINPAYLOADLEN + 2 + MINPAYLOADLEN;
    let max_payload_len = 2 + MAXPAYLOADLEN + 2 + MAXPAYLOADLEN;
    if payload_len < min_payload_len || payload_len > max_payload_len {
        return Err(ConvertError::InvalidPayloadLen {
            min: min_payload_len,
            payload: payload_len,
            max: max_payload_len,
        });
    }

    //check that the input slice is at least as long as the encoded len
    if sig.len() - 2 < payload_len {
        return Err(ConvertError::TooShort);
    }

    //retrieve R
    if sig[2] != 0x02 {
        return Err(ConvertError::InvalidRMarker(sig[2]));
    }

    let r_len = sig[3] as usize;
    if !payload_range.contains(&r_len) {
        return Err(ConvertError::InvalidRLen(r_len));
    }

    if R < r_len {
        return Err(ConvertError::TooShort);
    }

    //sig[4], after DER, after Payload, after marker after len
    let r = &sig[4..][..r_len];

    //retrieve S
    if sig[4 + r_len] != 0x02 {
        return Err(ConvertError::InvalidSMarker(sig[4 + r_len]));
    }

    let s_len = sig[4 + r_len + 1] as usize;
    if !payload_range.contains(&s_len) {
        return Err(ConvertError::InvalidSLen(s_len));
    }

    if S < s_len {
        return Err(ConvertError::TooShort);
    }

    //after r (4 + r_len), after marker, after len
    let s = &sig[4 + r_len + 2..][..s_len];

    //fill everything with 0 first
    out_r.fill(0);
    out_s.fill(0);

    //populate from the back
    out_r[R - r_len..][..r_len].copy_from_slice(r);
    out_s[S - s_len..][..s_len].copy_from_slice(s);

    Ok((r_len, s_len))
}

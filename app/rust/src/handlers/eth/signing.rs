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
use core::mem::MaybeUninit;

use crate::handlers::resources::{EthAccessors, ETH_UI};
use crate::parser::{ETH_MAINNET_ID, NONE_CHAIN_ID};
use crate::{handlers::eth::EthUi, parser::ParserError};
use bolos::{
    crypto::{bip32::BIP32Path, ecfp256::ECCInfo},
    hash::{Hasher, Keccak},
};
use zemu_sys::{Show, ViewError, Viewable};

use crate::{
    constants::{ApduError as Error, MAX_BIP32_PATH_DEPTH},
    crypto::{Curve, ECCInfoFlags},
    dispatcher::ApduHandler,
    handlers::resources::{
        StreamingAccessors, BUFFER, EXPECTED_BYTES, IS_LEGACY_TX, LAST_PACKET, PATH,
        RECEIVED_BYTES, SECOND_LAST_PACKET, STREAMING_CHAIN_ID, STREAMING_HASH, STREAMING_HASHER,
        STREAMING_MODE, STREAMING_MODE_USED, STREAMING_TX_TYPE,
    },
    parser::{bytes_to_u64, DisplayableItem, EthTransaction, FromBytes, U32_SIZE},
    sys,
    utils::{convert_der_to_rs, is_app_mode_blind_sign, ApduBufferRead},
};

use super::utils::get_tx_rlp_len;
use super::utils::parse_bip32_eth;

/// Convert a chain ID slice to a fixed-size 8-byte array.
/// Returns None if the slice is empty, otherwise copies up to 8 bytes.
fn chain_id_to_array(chain_id_slice: &[u8]) -> Option<[u8; 8]> {
    if chain_id_slice.is_empty() {
        return None;
    }
    let mut array = [0u8; 8];
    let len = core::cmp::min(chain_id_slice.len(), 8);
    array[..len].copy_from_slice(&chain_id_slice[..len]);
    Some(array)
}

pub struct Sign;

// Extract legacy chain ID by searching backwards for R/S markers
fn extract_legacy_chain_id_from_end(data: &[u8]) -> Option<[u8; 8]> {
    // Legacy transaction ends with [chain_id][r][s] where r/s are 0x80
    // We need to search backwards for the pattern
    if data.len() < 3 {
        return None; // Too short to contain chain_id + r + s
    }

    // Check for common empty R/S patterns at the end
    // RLP encoding of empty value is 0x80
    let ends_with_8080 =
        data.len() >= 2 && data[data.len() - 2] == 0x80 && data[data.len() - 1] == 0x80;

    if ends_with_8080 {
    } else {
        return None;
    }

    // Work backwards to find chain ID
    // For 0x8080 ending, chain ID is before these 2 bytes
    let chain_id_end = data.len() - 2;
    let mut chain_id_bytes = [0u8; 8];

    // Look for chain ID patterns
    // Common Avalanche chain ID: 0xa868 (43112 in decimal)
    // This is encoded as 0x82a868 in RLP (0x82 = prefix for 2-byte string, 0xa868 = value)
    if chain_id_end >= 3 && data[chain_id_end - 3] == 0x82 {
        // Two-byte chain ID with RLP prefix 0x82
        // Only store the 2 significant bytes, leave rest as zero
        chain_id_bytes[0] = data[chain_id_end - 2];
        chain_id_bytes[1] = data[chain_id_end - 1];
        return Some(chain_id_bytes);
    } else if chain_id_end >= 2 && data[chain_id_end - 2] == 0x81 {
        // Single-byte chain ID with RLP prefix 0x81
        chain_id_bytes[0] = data[chain_id_end - 1];
        return Some(chain_id_bytes);
    } else if chain_id_end > 0 {
        let potential_chain_byte = data[chain_id_end - 1];
        if potential_chain_byte > 0 && potential_chain_byte < 0x80 {
            // Direct single byte chain ID (no RLP prefix needed for values < 0x80)
            chain_id_bytes[0] = potential_chain_byte;
            return Some(chain_id_bytes);
        }
    }

    None
}

// Extract metadata from first packet for EIP-1559/EIP-2930 transactions
fn extract_tx_metadata_for_streaming(data: &[u8]) -> (bool, Option<[u8; 8]>) {
    // Try to parse transaction using same logic as normal mode
    let mut temp_tx = MaybeUninit::uninit();
    if let Ok(_) = EthTransaction::from_bytes_into(data, &mut temp_tx) {
        let temp_tx = unsafe { temp_tx.assume_init() };

        let is_typed = temp_tx.is_typed_tx();
        let chain_id_bytes = chain_id_to_array(temp_tx.chain_id());

        (is_typed, chain_id_bytes)
    } else {
        // If parsing fails, fall back to legacy (same as None chain_id)
        (false, None)
    }
}

#[allow(static_mut_refs)]
impl Sign {
    pub const SIGN_HASH_SIZE: usize = Keccak::<32>::DIGEST_LEN;
    pub const BUFFER_CAPACITY: usize = 16384; // device max flash length

    fn get_derivation_info() -> Result<&'static BIP32Path<MAX_BIP32_PATH_DEPTH>, Error> {
        match unsafe { PATH.acquire(Self) } {
            Ok(Some(some)) => Ok(some),
            _ => Err(Error::ApduCodeConditionsNotSatisfied),
        }
    }

    //(actual_size, [u8; MAX_SIGNATURE_SIZE])
    #[inline(never)]
    pub fn sign<const LEN: usize>(
        path: &BIP32Path<LEN>,
        // data: &[u8],
    ) -> Result<(ECCInfoFlags, usize, [u8; 100]), Error> {
        let sk = Curve.to_secret(path);
        let buffer = unsafe { BUFFER.acquire(Self)? };
        let data = Self::digest(buffer.read_exact())?;

        let mut out = [0; 100];
        let (flags, sz) = sk
            .sign(&data, &mut out[..])
            .map_err(|_| Error::ExecutionError)?;

        Ok((flags, sz, out))
    }

    // Sign a pre-computed hash (for blind signing)
    #[inline(never)]
    pub fn sign_hash<const LEN: usize>(
        path: &BIP32Path<LEN>,
        hash: &[u8; Self::SIGN_HASH_SIZE],
    ) -> Result<(ECCInfoFlags, usize, [u8; 100]), Error> {
        let sk = Curve.to_secret(path);

        let mut out = [0; 100];
        let (flags, sz) = sk
            .sign(hash, &mut out[..])
            .map_err(|_| Error::ExecutionError)?;

        Ok((flags, sz, out))
    }

    #[inline(never)]
    fn digest(to_hash: &[u8]) -> Result<[u8; Self::SIGN_HASH_SIZE], Error> {
        let mut hasher = {
            let mut k = MaybeUninit::uninit();
            Keccak::<32>::new_gce(&mut k).map_err(|_| Error::Unknown)?;

            //safe: initialized
            unsafe { k.assume_init() }
        };

        hasher.update(to_hash).map_err(|_| Error::Unknown)?;
        hasher.finalize().map_err(|_| Error::Unknown)
    }

    #[inline(never)]
    pub fn start_sign(txdata: &'static [u8], flags: &mut u32) -> Result<u32, Error> {
        // The ERC721 parser might need access to the NFT_INFO resource
        // also during the review part
        #[cfg(feature = "erc721")]
        unsafe {
            crate::handlers::resources::NFT_INFO.lock(crate::parser::ERC721Info)
        };

        // now parse the transaction
        let mut tx = MaybeUninit::uninit();
        let _ = EthTransaction::from_bytes_into(txdata, &mut tx).map_err(|_| Error::DataInvalid)?;

        // This does not hold true
        // keep it for reference only
        // some applications might append data at the end of an encoded
        // transaction, so skip it to get the right hash.
        //
        // this would also include the tx type, as required by EIP-2718
        // since the tx type is at the start of the data
        // let to_hash = txdata.len() - rem.len();
        // let to_hash = &txdata[..to_hash];

        let unsigned_hash = Self::digest(txdata).map_err(|_| Error::DataInvalid)?;
        let tx = unsafe { tx.assume_init() };

        let ui = SignUI {
            hash: unsigned_hash,
            is_typed: tx.is_typed_tx(),
            chain_id: chain_id_to_array(tx.chain_id()),
            tx,
        };

        crate::show_ui!(unsafe { ui.show(flags) })
    }

    #[inline(never)]
    pub fn start_parse(txdata: &'static [u8]) -> Result<(), ParserError> {
        // The ERC721 parser might need access to the NFT_INFO resource
        // also during the review part
        #[cfg(feature = "erc721")]
        unsafe {
            crate::handlers::resources::NFT_INFO.lock(crate::parser::ERC721Info)
        };

        // now parse the transaction
        let mut tx = MaybeUninit::uninit();
        let _ = EthTransaction::from_bytes_into(txdata, &mut tx)?;

        // This does not hold true, keep it just for reference
        // some applications might append data at the end of an encoded
        // transaction, so skip it to get the right hash.
        //
        // this would also include the tx type, as required by EIP-2718
        // since the tx type is at the start of the data
        // let to_hash = txdata.len() - rem.len();
        // let to_hash = &txdata[..to_hash];
        let unsigned_hash = Self::digest(txdata).map_err(|_| ParserError::UnexpectedError)?;
        let tx = unsafe { tx.assume_init() };

        let ui = EthUi::Tx(SignUI {
            hash: unsigned_hash,
            is_typed: tx.is_typed_tx(),
            chain_id: chain_id_to_array(tx.chain_id()),
            tx,
        });

        unsafe {
            ETH_UI.lock(EthAccessors::Tx).replace(ui);
        }
        Ok(())
    }

    #[inline(never)]
    fn finalize_streaming_hash() -> Result<(), ParserError> {
        let hasher = unsafe {
            STREAMING_HASHER
                .acquire(StreamingAccessors::EthSign)
                .map_err(|_| ParserError::UnexpectedError)?
                .take()
                .ok_or(ParserError::UnexpectedError)?
        };

        let hash = hasher
            .finalize()
            .map_err(|_| ParserError::UnexpectedError)?;

        // Mark that streaming mode was used for this transaction and store the hash
        unsafe {
            *STREAMING_MODE_USED.lock(StreamingAccessors::EthSign) = true;
            *STREAMING_HASH.lock(StreamingAccessors::EthSign) = Some(hash);
        }

        // Create a minimal SignUI with the pre-computed hash for blind signing
        // We need a dummy transaction object but it won't be displayed in blind signing mode
        // In blind signing, we only show the hash, not transaction details
        // So we can safely use a zeroed transaction structure as placeholder
        let tx: EthTransaction<'static> = unsafe { core::mem::zeroed() };

        // Retrieve stored transaction metadata for V calculation
        let is_typed = unsafe {
            let stored_is_typed = *STREAMING_TX_TYPE.lock(StreamingAccessors::EthSign);
            stored_is_typed
        };

        // Extract chain ID - for legacy transactions, extract from buffered packets
        let chain_id = unsafe {
            let is_legacy = *IS_LEGACY_TX.lock(StreamingAccessors::EthSign);

            if is_legacy {
                // Try to extract chain ID from buffered packets
                let last = LAST_PACKET.lock(StreamingAccessors::EthSign);
                let second_last = SECOND_LAST_PACKET.lock(StreamingAccessors::EthSign);

                // Combine last two packets if available
                let chain_id_from_end = if let (Some(last_packet), Some(second_last_packet)) =
                    (last.as_ref(), second_last.as_ref())
                {
                    // Extract actual lengths from first byte
                    let last_len = last_packet[0] as usize;
                    let second_last_len = second_last_packet[0] as usize;

                    // Combine packets using actual lengths
                    let mut combined = [0u8; 510];
                    let second_last_data = &second_last_packet[1..=second_last_len];
                    let last_data = &last_packet[1..=last_len];

                    combined[..second_last_len].copy_from_slice(second_last_data);
                    combined[second_last_len..second_last_len + last_len]
                        .copy_from_slice(last_data);

                    let total_len = second_last_len + last_len;
                    extract_legacy_chain_id_from_end(&combined[..total_len])
                } else if let Some(last_packet) = last.as_ref() {
                    // Single packet case (transaction fits in one packet)
                    let last_len = last_packet[0] as usize;
                    let last_data = &last_packet[1..=last_len];
                    extract_legacy_chain_id_from_end(last_data)
                } else {
                    None
                };

                // If we found chain ID in legacy packets, store it
                if let Some(chain_id_bytes) = chain_id_from_end {
                    *STREAMING_CHAIN_ID.lock(StreamingAccessors::EthSign) = Some(chain_id_bytes);
                    Some(chain_id_bytes)
                } else {
                    // Fallback to stored value (should be None for legacy)
                    *STREAMING_CHAIN_ID.lock(StreamingAccessors::EthSign)
                }
            } else {
                // For typed transactions, use previously extracted chain ID
                *STREAMING_CHAIN_ID.lock(StreamingAccessors::EthSign)
            }
        };

        // Create SignUI with the pre-computed hash and stored metadata
        let ui = EthUi::Tx(SignUI {
            hash,     // Use the pre-computed hash from streaming
            is_typed, // Transaction type from first packet
            chain_id, // Chain ID from first packet (for correct V calculation)
            tx,       // Dummy transaction (won't be displayed in blind signing)
        });

        // Store the UI for later signing
        unsafe {
            ETH_UI.lock(EthAccessors::Tx).replace(ui);
        }

        // Clean up streaming state
        unsafe {
            *STREAMING_MODE.lock(StreamingAccessors::EthSign) = false;
            let _ = STREAMING_HASHER.release(StreamingAccessors::EthSign);
            *EXPECTED_BYTES.lock(StreamingAccessors::EthSign) = 0;
            *RECEIVED_BYTES.lock(StreamingAccessors::EthSign) = 0;

            // Clean up legacy-specific resources
            *IS_LEGACY_TX.lock(StreamingAccessors::EthSign) = false;
            *LAST_PACKET.lock(StreamingAccessors::EthSign) = None;
            *SECOND_LAST_PACKET.lock(StreamingAccessors::EthSign) = None;
        }

        // Return Ok - the hash has been computed successfully
        // and SignUI has been created for blind signing
        Ok(())
    }

    pub fn parse(buffer: ApduBufferRead<'_>) -> Result<bool, ParserError> {
        crate::zlog("EthSign::parse\x00");

        // hw-app-eth encodes the packet type in p1
        // with 0x00 being init and 0x80 being next
        //
        // the end of the transmission is implicit based on the received data
        // an eth transaction is RLP encoded (https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#definition)
        // with the first byte being the version (0x01 EIP2930 or 0x02 EIP1559 or legacy if neither/missing)
        // and then a RLP list
        //
        // therefore, the data received self-describes how many bytes the app can expect and
        // when all data has been received

        let packet_type = buffer.p1();

        match packet_type {
            //init
            0x00 => {
                let payload = buffer.payload().map_err(|_| ParserError::NoData)?;
                //parse path to verify it's the data we expect
                let (rest, bip32_path) =
                    parse_bip32_eth(payload).map_err(|_| ParserError::InvalidPath)?;

                unsafe {
                    PATH.lock(Self).replace(bip32_path);
                }

                //parse the length of the RLP message
                let (read, to_read) =
                    get_tx_rlp_len(rest).map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let total_size = (to_read as usize).saturating_add(read);

                // Check if transaction is too large for buffer
                if total_size > Self::BUFFER_CAPACITY {
                    // Verify blind signing is enabled
                    if !is_app_mode_blind_sign() {
                        return Err(ParserError::BlindSignNotEnabled);
                    }

                    // Detect if transaction is legacy (doesn't start with 0x01 or 0x02)
                    let is_legacy = !rest.is_empty() && rest[0] != 0x01 && rest[0] != 0x02;

                    // Extract metadata using same parsing logic as normal mode
                    let (is_typed, chain_id_bytes) = if is_legacy {
                        // For legacy, we can't get chain ID from first packet
                        (false, None)
                    } else {
                        extract_tx_metadata_for_streaming(rest)
                    };

                    // Initialize streaming hash mode
                    let mut hasher =
                        Keccak::<32>::new().map_err(|_| ParserError::UnexpectedError)?;

                    // Hash the data we have so far
                    let len = core::cmp::min(total_size, rest.len());
                    hasher
                        .update(&rest[..len])
                        .map_err(|_| ParserError::UnexpectedError)?;

                    // Store state for subsequent packets
                    unsafe {
                        use crate::handlers::resources::{STREAMING_CHAIN_ID, STREAMING_TX_TYPE};

                        STREAMING_HASHER
                            .lock(StreamingAccessors::EthSign)
                            .replace(hasher);
                        *STREAMING_MODE.lock(StreamingAccessors::EthSign) = true;
                        *EXPECTED_BYTES.lock(StreamingAccessors::EthSign) = to_read;
                        *RECEIVED_BYTES.lock(StreamingAccessors::EthSign) =
                            (len as u64).saturating_sub(read as u64);

                        // Store transaction metadata for V calculation
                        *STREAMING_TX_TYPE.lock(StreamingAccessors::EthSign) = is_typed;
                        *STREAMING_CHAIN_ID.lock(StreamingAccessors::EthSign) = chain_id_bytes;

                        // Track if this is a legacy transaction
                        *IS_LEGACY_TX.lock(StreamingAccessors::EthSign) = is_legacy;

                        // For legacy, store first packet for potential single-packet case
                        if is_legacy && len <= 254 {
                            let mut first_packet = [0u8; 255];
                            first_packet[0] = len as u8; // Store actual length
                            first_packet[1..=len].copy_from_slice(&rest[..len]);
                            LAST_PACKET
                                .lock(StreamingAccessors::EthSign)
                                .replace(first_packet);
                        }
                    }

                    // Check if complete in first packet
                    if total_size <= rest.len() {
                        Self::finalize_streaming_hash()?;
                        return Ok(true);
                    }

                    return Ok(false); // Need more packets
                }

                // Normal path for small transactions
                let len = core::cmp::min(total_size, rest.len());
                let buffer = unsafe { BUFFER.lock(Self) };
                buffer.reset();

                buffer
                    .write(&rest[..len])
                    .map_err(|_| ParserError::UnexpectedError)?;

                //if the number of bytes read and the number of bytes to read
                // is the same as what we read...
                if (to_read as usize).saturating_add(read).saturating_sub(len) == 0 {
                    //then we actually had all bytes in this tx!
                    // we should sign directly
                    Self::start_parse(buffer.read_exact())?;

                    return Ok(true);
                }

                Ok(false)
            }
            //next
            0x80 => {
                let payload = buffer.payload().map_err(|_| ParserError::NoData)?;

                // Check if we're in streaming mode
                let streaming = unsafe { *STREAMING_MODE.lock(StreamingAccessors::EthSign) };

                if streaming {
                    // For legacy transactions, buffer packets for chain ID extraction
                    let is_legacy = unsafe { *IS_LEGACY_TX.lock(StreamingAccessors::EthSign) };

                    if is_legacy && payload.len() > 0 {
                        // Rotate packet buffers: last -> second_last, current -> last
                        unsafe {
                            let last = LAST_PACKET.lock(StreamingAccessors::EthSign);
                            let second_last = SECOND_LAST_PACKET.lock(StreamingAccessors::EthSign);

                            // Move last to second_last (if it exists)
                            *second_last = *last;

                            // Store current packet with length in first byte
                            if payload.len() <= 254 {
                                let mut new_last = [0u8; 255];
                                new_last[0] = payload.len() as u8; // Store actual length
                                new_last[1..=payload.len()].copy_from_slice(payload);
                                last.replace(new_last);
                            }
                        }
                    }

                    // Update hash with new data
                    unsafe {
                        if let Some(hasher) = STREAMING_HASHER
                            .acquire(StreamingAccessors::EthSign)
                            .map_err(|_| ParserError::UnexpectedError)?
                        {
                            hasher
                                .update(payload)
                                .map_err(|_| ParserError::UnexpectedError)?;
                        } else {
                            return Err(ParserError::UnexpectedError);
                        }
                    }

                    // Update received bytes counter
                    let received_bytes =
                        unsafe { RECEIVED_BYTES.lock(StreamingAccessors::EthSign) };
                    *received_bytes = received_bytes.saturating_add(payload.len() as u64);

                    let expected_bytes =
                        unsafe { *EXPECTED_BYTES.lock(StreamingAccessors::EthSign) };

                    if *received_bytes >= expected_bytes {
                        Self::finalize_streaming_hash()?;
                        return Ok(true);
                    }

                    return Ok(false); // Need more packets
                }

                // Normal buffer append path
                let buffer = unsafe {
                    BUFFER
                        .acquire(Self)
                        .map_err(|_| ParserError::UnexpectedError)?
                };

                //we could unwrap here as this data should be guaranteed correct
                // we read back what we wrote to see how many bytes we expect
                // to have to collect
                let (read, to_read) = get_tx_rlp_len(buffer.read_exact())
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;

                // let's ignore the little header at the start
                let rlp_read = buffer.read_exact().len() - read;

                //either the entire buffer of the remaining bytes we expect
                let missing = to_read as usize - rlp_read;
                let len = core::cmp::min(missing, payload.len());

                buffer
                    .write(&payload[..len])
                    .map_err(|_| ParserError::UnexpectedError)?;

                if missing - len == 0 {
                    //we read all the missing bytes so we can proceed with the signature
                    // nwo
                    Self::start_parse(buffer.read_exact())?;
                    return Ok(true);
                }

                Ok(false)
            }
            _ => Err(ParserError::UnexpectedData),
        }
    }
}

#[allow(static_mut_refs)]
impl ApduHandler for Sign {
    #[inline(never)]
    fn handle(flags: &mut u32, tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("EthSign::handle\x00");

        *tx = 0;

        // hw-app-eth encodes the packet type in p1
        // with 0x00 being init and 0x80 being next
        //
        // the end of the transmission is implicit based on the received data
        // an eth transaction is RLP encoded (https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/#definition)
        // with the first byte being the version (0x01 EIP2930 or 0x02 EIP1559 or legacy if neither/missing)
        // and then a RLP list
        //
        // therefore, the data received self-describes how many bytes the app can expect and
        // when all data has been received

        let packet_type = buffer.p1();

        match packet_type {
            //init
            0x00 => {
                let payload = buffer.payload().map_err(|_| Error::WrongLength)?;
                //parse path to verify it's the data we expect
                let (rest, bip32_path) =
                    parse_bip32_eth(payload).map_err(|_| Error::DataInvalid)?;

                unsafe {
                    PATH.lock(Self).replace(bip32_path);
                }

                //parse the length of the RLP message
                let (read, to_read) = get_tx_rlp_len(rest)?;
                let len = core::cmp::min((to_read as usize).saturating_add(read), rest.len());

                //write the rest to the swapping buffer so we persist this data
                let buffer = unsafe { BUFFER.lock(Self) };
                buffer.reset();

                buffer
                    .write(&rest[..len])
                    .map_err(|_| Error::ExecutionError)?;

                //if the number of bytes read and the number of bytes to read
                // is the same as what we read...
                if (to_read as usize).saturating_add(read).saturating_sub(len) == 0 {
                    //then we actually had all bytes in this tx!
                    // we should sign directly
                    *tx = Self::start_sign(buffer.read_exact(), flags)?;
                }

                Ok(())
            }
            //next
            0x80 => {
                let payload = buffer.payload().map_err(|_| Error::WrongLength)?;

                let buffer = unsafe { BUFFER.acquire(Self)? };

                //we could unwrap here as this data should be guaranteed correct
                // we read back what we wrote to see how many bytes we expect
                // to have to collect
                let (read, to_read) = get_tx_rlp_len(buffer.read_exact())?;

                // let's ignore the little header at the start
                let rlp_read = buffer.read_exact().len() - read;

                //either the entire buffer of the remaining bytes we expect
                let missing = to_read as usize - rlp_read;
                let len = core::cmp::min(missing, payload.len());

                buffer
                    .write(&payload[..len])
                    .map_err(|_| Error::ExecutionError)?;

                if missing - len == 0 {
                    //we read all the missing bytes so we can proceed with the signature
                    // nwo
                    *tx = Self::start_sign(buffer.read_exact(), flags)?;
                }

                Ok(())
            }
            _ => Err(Error::InvalidP1P2),
        }
    }
}

pub(crate) struct SignUI {
    pub(crate) hash: [u8; Sign::SIGN_HASH_SIZE],
    pub(crate) tx: EthTransaction<'static>,
    pub(crate) is_typed: bool, // For correct V calculation in blind signing
    pub(crate) chain_id: Option<[u8; 8]>, // Store raw chain ID bytes for V calculation (fixed array)
}

impl Viewable for SignUI {
    fn num_items(&mut self) -> Result<u8, ViewError> {
        self.tx.num_items()
    }

    #[inline(never)]
    fn render_item(
        &mut self,
        item_n: u8,
        title: &mut [u8],
        message: &mut [u8],
        page: u8,
    ) -> Result<u8, ViewError> {
        self.tx.render_item(item_n, title, message, page)
    }

    fn accept(&mut self, out: &mut [u8]) -> (usize, u16) {
        let path = match Sign::get_derivation_info() {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        let (flags, sig_size, mut sig) = match Sign::sign_hash(path, &self.hash) {
            Err(e) => return (0, e as _),
            Ok(k) => k,
        };

        //reset globals to avoid skipping `Init`
        if let Err(e) = cleanup_globals() {
            return (0, e as _);
        }

        let mut tx = 0;

        //write signature as VRS

        // It is necessary to write the right V
        // component as it depends on the chainID(lowest byte) and the
        // parity of the last byte of the S component, this procedure is
        // defined by EIP-155.
        //
        // Check for typed transactions - use stored metadata if available
        // This ensures correct V calculation even in blind signing mode
        if self.is_typed {
            //write V, which is the oddity of the signature
            out[tx] = flags.contains(ECCInfo::ParityOdd) as u8;
            tx += 1;
        } else {
            // Use stored chain_id if available (for blind signing), otherwise get from tx
            let chain_id = self
                .chain_id
                .as_ref()
                .map(|v| {
                    // For stored chain_id, find the actual length (skip trailing zeros)
                    // This matches how normal mode works with tx.chain_id()
                    let mut len = v.len();
                    while len > 1 && v[len - 1] == 0 {
                        len -= 1;
                    }
                    &v[..len]
                })
                .unwrap_or_else(|| self.tx.chain_id());

            if chain_id.is_empty() {
                // according to app-ethereum this is the legacy non eip155 conformant
                // so V should be made before EIP155 which had
                // 27 + {0, 1}
                // 27, decided by the parity of Y
                // see https://bitcoin.stackexchange.com/a/112489
                //     https://ethereum.stackexchange.com/a/113505
                //     https://eips.ethereum.org/EIPS/eip-155
                out[tx] = 27 + flags.contains(ECCInfo::ParityOdd) as u8;
            } else {
                // app-ethereum reads the first 4 bytes then cast it to an u8
                // this is not good but it relies on hw-eth-app lib from ledger
                // to recover the right chain_id from the V component being computed here, and
                // which is returned with the signature
                let len = core::cmp::min(U32_SIZE, chain_id.len());
                if let Ok(chain_id) = bytes_to_u64(&chain_id[..len]) {
                    // Verify chain_id
                    if chain_id == NONE_CHAIN_ID || chain_id == ETH_MAINNET_ID {
                        return (0, Error::DataInvalid as _);
                    }
                    let v = (35 + flags.contains(ECCInfo::ParityOdd) as u32)
                        .saturating_add((chain_id as u32) << 1);
                    out[tx] = v as u8;
                }
            }
            tx += 1;
        }

        //set to 0x30 for the DER conversion
        sig[0] = 0x30;
        {
            let mut r = [0; 33];
            let mut s = [0; 33];

            //write as R S (V written earlier)
            // this will write directly to buffer
            match convert_der_to_rs(&sig[..sig_size], &mut r, &mut s) {
                Ok(_) => {
                    //format R and S by only having 32 bytes each,
                    // skipping the first byte if necessary
                    // if we have less than 32 bytes we just have 0s at the start
                    // this is consistent with the fact that in `convert_der_to_rs`
                    // we put the bytes at the end of the buffer first
                    let r = &r[1..];
                    let s = &s[1..];

                    out[tx..][..32].copy_from_slice(r);
                    tx += 32;

                    out[tx..][..32].copy_from_slice(s);
                    tx += 32;
                }
                Err(_) => return (0, Error::ExecutionError as _),
            }
        }

        (tx, Error::Success as _)
    }

    fn reject(&mut self, _: &mut [u8]) -> (usize, u16) {
        let _ = cleanup_globals();
        (0, Error::CommandNotAllowed as _)
    }
}

#[allow(static_mut_refs)]
pub fn cleanup_globals() -> Result<(), Error> {
    unsafe {
        if let Ok(path) = PATH.acquire(Sign) {
            path.take();

            //let's release the lock for the future
            let _ = PATH.release(Sign);
        }

        if let Ok(buffer) = BUFFER.acquire(Sign) {
            buffer.reset();

            //let's release the lock for the future
            let _ = BUFFER.release(Sign);
        }

        // Reset streaming mode used flag, hash, and metadata
        use crate::handlers::resources::{
            STREAMING_CHAIN_ID, STREAMING_HASH, STREAMING_MODE_USED, STREAMING_TX_TYPE,
        };
        *STREAMING_MODE_USED.lock(StreamingAccessors::EthSign) = false;
        *STREAMING_HASH.lock(StreamingAccessors::EthSign) = None;
        *STREAMING_TX_TYPE.lock(StreamingAccessors::EthSign) = false;
        *STREAMING_CHAIN_ID.lock(StreamingAccessors::EthSign) = None;

        // Forcefully acquire the resource as it is not longer in use
        // transaction was rejected.
        #[cfg(feature = "erc721")]
        {
            crate::handlers::resources::NFT_INFO.lock(Sign).take();
            //let's release the lock for the future
            _ = crate::handlers::resources::NFT_INFO.release(Sign);
        }
    }

    //if we failed to aquire then someone else is using it anyways
    Ok(())
}

/// Check if streaming mode was used for the last ETH transaction
#[no_mangle]
pub unsafe extern "C" fn rs_eth_was_streaming_mode_used() -> bool {
    use crate::handlers::resources::STREAMING_MODE_USED;

    *STREAMING_MODE_USED.lock(StreamingAccessors::EthSign)
}

/// Get the computed hash from streaming mode (returns true if hash is available)
#[no_mangle]
pub unsafe extern "C" fn rs_eth_get_streaming_hash(hash_buffer: *mut u8, buffer_len: u16) -> bool {
    use crate::handlers::resources::STREAMING_HASH;

    if buffer_len < 32 {
        return false;
    }

    let hash_option = *STREAMING_HASH.lock(StreamingAccessors::EthSign);
    if let Some(hash) = hash_option {
        let buffer_slice = std::slice::from_raw_parts_mut(hash_buffer, 32);
        buffer_slice.copy_from_slice(&hash);
        true
    } else {
        false
    }
}

/// Get the number of items for blind signing display (always returns 1)
#[no_mangle]
pub unsafe extern "C" fn _getNumItemsBlindSign(num_items: *mut u8) -> u32 {
    use crate::parser::ParserError;

    if num_items.is_null() {
        return ParserError::NoData as u32;
    }

    // For blind signing, we always show 1 item: the hash
    *num_items = 1;
    ParserError::ParserOk as u32
}

/// Get a specific item for blind signing display
#[no_mangle]
pub unsafe extern "C" fn _getItemBlindSign(
    display_idx: i8,
    out_key: *mut i8,
    out_key_len: u16,
    out_value: *mut i8,
    out_value_len: u16,
    page_idx: u8,
    page_count: *mut u8,
) -> u32 {
    use crate::handlers::handle_ui_message;
    use crate::parser::ParserError;
    use bolos::{pic_str, PIC};

    // Validate input parameters
    if out_key.is_null() || out_value.is_null() || page_count.is_null() {
        return ParserError::NoData as u32;
    }

    // We only have 1 item for blind signing
    if display_idx != 0 {
        return ParserError::DisplayIdxOutOfRange as u32;
    }

    crate::zlog("_getItemBlindSign\n");

    // Set the title using pic_str!
    let label = pic_str!(b"Transaction hash");
    let key_slice = std::slice::from_raw_parts_mut(out_key as *mut u8, out_key_len as usize);

    if (label.len() + 1) > out_key_len as usize {
        return ParserError::UnexpectedBufferEnd as u32;
    }

    key_slice[..label.len()].copy_from_slice(label);
    key_slice[label.len()] = 0; // null terminator

    // Get the actual transaction hash from streaming mode
    let mut hash_buffer = [0u8; 32];
    let hash_available = rs_eth_get_streaming_hash(hash_buffer.as_mut_ptr(), 32);

    if !hash_available {
        crate::zlog("_getItemBlindSign: No hash available\n");
        return ParserError::NoData as u32;
    }

    // Format hash as hex string: "0x" + 64 hex chars = 66 chars total
    let mut hex_string = [0u8; 66];
    hex_string[0] = b'0';
    hex_string[1] = b'x';

    // Convert each byte to 2 hex characters
    for (i, &byte) in hash_buffer.iter().enumerate() {
        let hex_pos = 2 + (i * 2);
        let high_nibble = (byte >> 4) & 0x0f;
        let low_nibble = byte & 0x0f;

        hex_string[hex_pos] = if high_nibble < 10 {
            b'0' + high_nibble
        } else {
            b'a' + (high_nibble - 10)
        };

        hex_string[hex_pos + 1] = if low_nibble < 10 {
            b'0' + low_nibble
        } else {
            b'a' + (low_nibble - 10)
        };
    }

    let value_slice = std::slice::from_raw_parts_mut(out_value as *mut u8, out_value_len as usize);

    // Use handle_ui_message to properly handle paging
    match handle_ui_message(&hex_string, value_slice, page_idx) {
        Ok(pages) => {
            *page_count = pages;
            ParserError::ParserOk as u32
        }
        Err(_) => ParserError::UnexpectedError as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_decoder() {
        let data = hex::decode("02f878018402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c080a01e514f7fc78197c66589083cc8fd06376bae627a4080f5fb58d52d90c0df340da049b048717f215e622c93722ff5b1e38e1d1a4ab9e26a39183969a34a5f8dea75").unwrap();

        let (read, to_read) = get_tx_rlp_len(&data).expect("unable to minimally parse tx data");

        assert_eq!(read, 3);
        assert_eq!(to_read, 0x78);
    }
}

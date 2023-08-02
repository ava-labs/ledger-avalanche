/*******************************************************************************
*   (c) 2022 Zondax AG
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
use super::prelude::*;
use std::collections::HashMap;

use arrayref::{array_ref, array_refs};
use itertools::Itertools;

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    elliptic_curve::sec1::FromEncodedPoint,
    EncodedPoint, PublicKey,
};

use bolos::{
    crypto::bip32::BIP32Path,
    hash::{Hasher, Sha256},
};
use rand::Rng;

use constants::{
    APDU_INDEX_CLA, APDU_INDEX_INS, APDU_INDEX_LEN, APDU_INDEX_P1, APDU_INDEX_P2,
    INS_GET_PUBLIC_KEY, INS_SIGN, INS_SIGN_HASH,
};

#[test]
#[ignore]
fn p_create_chain() {
    const NUMBER_OF_SIGNERS: usize = 25500;
    const MAX_N_SIGNERS: usize = u8::MAX as usize;
    const MAX_COMPONENT: u32 = u32::MAX & !0x8000_0000;

    let paths = (0..NUMBER_OF_SIGNERS)
        .map(|_| {
            let mut rng = rand::thread_rng();

            (
                rng.gen_range(0..MAX_COMPONENT),
                rng.gen_range(0..MAX_COMPONENT),
            )
        })
        .chunks(MAX_N_SIGNERS);

    let mut verifications = HashMap::new();
    for signers in paths.into_iter() {
        let signers = signers.map(|(a, b)| [a, b]).collect::<Vec<_>>();
        verifications.extend(p_create_chain_inner(signers.as_slice()));
    }

    let mut counter = 0;
    verifications
        .into_iter()
        .filter(|(_, v)| !v)
        .for_each(|(signer, v)| {
            counter += 1;
            match v {
                true => unreachable!(),
                false => eprintln!("{} verification ok!", signer),
            }
        });

    assert_eq!(counter, 0, "verification failed")
}

fn p_create_chain_inner(signers: &[[u32; 2]]) -> HashMap<String, bool> {
    const ROOT: [u32; 3] = [0x8000_0000 + 44, 0x8000_0000 + 9000, 0];

    let op = AvaxSign::new(ROOT, signers, P_CREATE_CHAIN, &[]);

    let result = op.send();
    let mut verifications = HashMap::with_capacity(result.len());

    let hash = Sha256::digest(P_CREATE_CHAIN).unwrap();
    for (path, sig) in result {
        let pkey = AvaxSign::get_pubkey_of(path);
        let pkey = VerifyingKey::from(pkey);

        let (_, r, s) = array_refs![array_ref!(sig, 0, 65), 1, 32, 32];
        let sig = Signature::from_scalars(*r, *s).expect("not a valid RS signature");

        let verified = pkey.verify(&hash, &sig).is_ok();

        verifications.entry(path.to_string()).or_insert(verified);
    }

    verifications
}

const P_CREATE_CHAIN: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xdb, 0xcf,
    0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76, 0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8, 0x29, 0x37,
    0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0, 0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb, 0x00, 0x00,
    0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0xee, 0x5b, 0xe5, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xda, 0x2b, 0xee, 0x01, 0xbe, 0x82,
    0xec, 0xc0, 0x0c, 0x34, 0xf3, 0x61, 0xed, 0xa8, 0xeb, 0x30, 0xfb, 0x5a, 0x71, 0x5c, 0x00, 0x00,
    0x00, 0x01, 0xdf, 0xaf, 0xbd, 0xf5, 0xc8, 0x1f, 0x63, 0x5c, 0x92, 0x57, 0x82, 0x4f, 0xf2, 0x1c,
    0x8e, 0x3e, 0x6f, 0x7b, 0x63, 0x2a, 0xc3, 0x06, 0xe1, 0x14, 0x46, 0xee, 0x54, 0x0d, 0x34, 0x71,
    0x1a, 0x15, 0x00, 0x00, 0x00, 0x01, 0xdb, 0xcf, 0x89, 0x0f, 0x77, 0xf4, 0x9b, 0x96, 0x85, 0x76,
    0x48, 0xb7, 0x2b, 0x77, 0xf9, 0xf8, 0x29, 0x37, 0xf2, 0x8a, 0x68, 0x70, 0x4a, 0xf0, 0x5d, 0xa0,
    0xdc, 0x12, 0xba, 0x53, 0xf2, 0xdb, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x01, 0xd2, 0x97, 0xb5,
    0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x86,
    0xd0, 0x7c, 0xd6, 0x02, 0x18, 0x66, 0x18, 0x63, 0xe0, 0x11, 0x65, 0x52, 0xdc, 0xcd, 0x5b, 0xd8,
    0x4c, 0x56, 0x4b, 0xd2, 0x9d, 0x71, 0x81, 0xdb, 0xdd, 0xd5, 0xec, 0x61, 0x61, 0x04, 0x00, 0x08,
    0x45, 0x50, 0x49, 0x43, 0x20, 0x41, 0x56, 0x4d, 0x61, 0x76, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x73, 0x65, 0x63, 0x70,
    0x32, 0x35, 0x36, 0x6b, 0x31, 0x66, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x41, 0x73, 0x73, 0x65, 0x74, 0x41, 0x6c, 0x69,
    0x61, 0x73, 0x54, 0x65, 0x73, 0x74, 0x00, 0x00, 0x05, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x66, 0x72, 0x6f, 0x6d, 0x20, 0x73, 0x6e, 0x6f, 0x77, 0x66,
    0x6c, 0x61, 0x6b, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x76, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x68,
    0x65, 0x00, 0x0a, 0x54, 0x65, 0x73, 0x74, 0x20, 0x41, 0x73, 0x73, 0x65, 0x74, 0x00, 0x04, 0x54,
    0x45, 0x53, 0x54, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfb, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x3c, 0xb7, 0xd3, 0x84,
    0x2e, 0x8c, 0xee, 0x6a, 0x0e, 0xbd, 0x09, 0xf1, 0xfe, 0x88, 0x4f, 0x68, 0x61, 0xe1, 0xb2, 0x9c,
    0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
];

pub struct AvaxSign {
    prefix: BIP32Path<3>,
    signers: Vec<BIP32Path<2>>,
    change: Vec<BIP32Path<2>>,
    msg: Vec<u8>,
}

impl AvaxSign {
    pub fn new(prefix: [u32; 3], signers: &[[u32; 2]], msg: &[u8], change: &[[u32; 2]]) -> Self {
        let prefix = BIP32Path::new(prefix).unwrap();
        let signers = signers
            .iter()
            .map(|signer| BIP32Path::new(signer.iter().cloned()).unwrap())
            .collect();
        let change = change
            .iter()
            .map(|change| BIP32Path::new(change.iter().cloned()).unwrap())
            .collect();

        Self {
            prefix,
            signers,
            change,
            msg: Vec::from(msg),
        }
    }

    /// Retrieve the message prefixed with the change paths
    fn msg_to_send(&self) -> Vec<u8> {
        let change_nums = self.change.len();

        //4 byte per component, 2 components, 1 is the len of the path
        let mut out = Vec::with_capacity(self.msg.len() + 1 + change_nums * (4 * 2 + 1));
        // number of change paths and then the change paths with the usual serialization
        out.push(change_nums as u8);

        let serialized_change = self.change.iter().flat_map(|path| path.serialize());
        out.extend(serialized_change);

        //change_paths are prefixed to the message (for purposes of sending the payload)
        out.extend_from_slice(&self.msg);

        out
    }

    /// Get the data to send the apdu directly
    fn get_chunks(&self) -> Vec<[u8; 260]> {
        let mut chunks = chunk(
            INS_SIGN,
            0x03,
            //first message is only the prefix path
            self.prefix.serialize().as_slice(),
            &self.msg_to_send(),
        );

        //set first chunk as "first message"
        chunks[0][APDU_INDEX_P2] = 0x01;

        chunks
    }

    //get the chunks to send to the handler to retrieve the signatres
    fn retrieve(&self) -> Vec<(&BIP32Path<2>, [u8; 260])> {
        let mut messages = Vec::with_capacity(self.signers.len());

        let mut buffer = [0; 260];
        buffer[APDU_INDEX_CLA] = CLA;
        buffer[APDU_INDEX_INS] = INS_SIGN_HASH;
        buffer[APDU_INDEX_P2] = 0;
        let buffer = buffer; //immutable

        for (i, signer) in self.signers.iter().enumerate() {
            let mut buf = buffer;
            buf[APDU_INDEX_P1] = if i == self.signers.len() - 1 {
                0x02 //next message
            } else {
                0x03 //last message
            };

            let path = signer.serialize();
            buf[APDU_INDEX_LEN] = path.len() as u8;
            buf[APDU_INDEX_LEN + 1..][..path.len()].copy_from_slice(&path);

            messages.push((signer, buf))
        }

        messages
    }

    /// Perform the signing and retireve the signatures
    pub fn send(self) -> Vec<(BIP32Path<5>, Vec<u8>)> {
        //first, send the payload
        // which is the change paths + the message
        for (i, mut chunk) in self.get_chunks().into_iter().enumerate() {
            let response = handle_apdu(&mut 0, &mut 0, 260, &mut chunk);

            if response[0] != 0x90 || response[1] != 0x00 {
                panic!(
                    "unexpected response 0x{} for chunk #{} when signing",
                    hex::encode(response),
                    i
                );
            }
        }

        let mut output = Vec::with_capacity(self.signers.len());
        //next, retrieve the signatures
        for (i, (signer, mut chunk)) in self.retrieve().into_iter().enumerate() {
            let response = handle_apdu(&mut 0, &mut 0, 260, &mut chunk);
            let last_bytes = &response[response.len() - 2..];

            if last_bytes[0] != 0x90 || last_bytes[1] != 0x00 {
                panic!(
                    "unexpected response 0x{} for signature #{}",
                    hex::encode(response),
                    i
                );
            }

            let signer = self
                .prefix
                .components()
                .iter()
                .chain(signer.components().iter())
                .cloned();
            let signer = BIP32Path::new(signer).unwrap();

            output.push((signer, response[..response.len() - 2].to_vec()));
        }

        output
    }

    pub fn get_pubkey_of(path: BIP32Path<5>) -> PublicKey {
        let mut buffer = [0; 260];

        let path_bytes = path.serialize();
        buffer[0] = CLA;
        buffer[1] = INS_GET_PUBLIC_KEY;
        buffer[2] = 0;
        buffer[3] = 0;
        buffer[4] = 2 + path_bytes.len() as u8;
        buffer[5] = 0;
        buffer[6] = 0;
        buffer[7..][..path_bytes.len()].copy_from_slice(&path_bytes);

        let response = handle_apdu(&mut 0, &mut 0, 5 + 2 + path_bytes.len() as u32, &mut buffer);
        let last_bytes = &response[response.len() - 2..];
        if last_bytes[0] != 0x90 || last_bytes[1] != 0x00 {
            panic!(
                "unexpected response 0x{} when retrieving address {:?}",
                hex::encode(response),
                path
            );
        }

        let pkey_len = response[0] as usize;
        let point = EncodedPoint::from_bytes(&response[1..][..pkey_len]).expect("valid point");

        Option::from(PublicKey::from_encoded_point(&point)).unwrap_or_else(|| {
            panic!(
                "not a valid publickey (0x{}) for path {:?}",
                hex::encode(&response[1..][..64]),
                path
            )
        })
    }
}

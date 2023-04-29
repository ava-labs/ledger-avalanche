/** ******************************************************************************
 *  (c) 2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu from '@zondax/zemu'
import { cartesianProduct, defaultOptions, models, btc_models, BTC_PATH } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import {DefaultWalletPolicy, WalletPolicy, PsbtV2} from '@zondax/ledger-avalanche-app'

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'

// We got this value from https://iancoleman.io/bip39/
// using our testing mnemonic and BTC_PATH
const EXPECTED_EXTENDED_PUBKEY =  "xpub6DSxz6qdmgbeqgrLcwHydNfNfs9B673zNrwYUaBBGHe7fiGv2hQ4qDAvCfY2jhKPfut6imCptyMo3cKMozd5qCbUoMVwjPCNfZtJ1Sd1nsN"


const BTC_DATA = [
  {
    name: 'psbt_1x1',
    op: Buffer.from(
      "cHNidP8BAFIBAAAAATV9s+6h3PHYe+DxhSTnrjOW73TbNDNubsAo0s2EdQQkBwAAAAAAAAAAAWC5BVrwdQcAFgAUm1DPkz7zd8wtU8Drs6L7TZwfBPAAAAAAAAEA/W0CAgAAAANqBm9+L5N0mQP8OO7XrOIwFmmTCMIsSWaMwZWwf4mRrgwAAABQ4I918ym8qAy4pwS/+Q2Cj0AEkKBGUgKpgi1/HiCidoYb3hlqBKKi6O1AL+4rv9smGlTtrRa5fQAMAD4SYVImDB4CM678km58BQWc1osdkmwAAAAAIQudwEQ6djtGrmjE1w98ATRAGTwtXbxGnsKET+AzVXMUAAAAUPy56gUk3qUw5BAlUJDFJivIoC0bHPIwdEfD50oqmHhvhW9fxyaCxpLBfq+hPxGW7yAOhz8JSnp/BMjAcSqll3nOXsBhE6gQh8eGt29BzlFAAAAAANzt3KLMJXU0P8Er7H2BOvXOQQJrRlCgLFUnb3nfwqzGEgAAAFAhYS7rhLISpEDnOEqf/1B7w2jdIz673DONojokUKhonusa1XIIZ0IyUasrUhqs5xkK0dGvaTvM7pzPNRcSp2yUOSczNgUUs5U5wr30zuj/AQAAAAAI7qskAwAAAAAWABTzWyeOln/cq8PSXzCUV0xiSvZrmjKI0wAAAAAAFgAU5PeIsfHFZMkVg2BIX5juSuwzkSCX2s0CAAAAABYAFLQKVNrRXh90eCQLE6oMQyrW0xZuCaZPAAAAAAAWABT9FmZ4+Gl0ch689uyWYyCr7V6hpjSxWgAAAAAAFgAUHNaf/aSq2y/SYaMyZEGyWXLsL1lEnbQAAAAAABYAFN+48mNiH0xQmlpY7DMfO6AsC2CFvTfxBQAAAAAWABT8RWoDPRu4ib/ow7HI92CtAZFB0wBAB1rwdQcAFgAUapAOdOdZbSCUodkw2zY+SLDx1pMAAAAAAQEfAEAHWvB1BwAWABRqkA5051ltIJSh2TDbNj5IsPHWkyIGAkQXMQsqCQ7wz3/6ilrRVFP4SWB/W5C7YeOM4NY44NnCGJEIYxQsAACAPAAAgAAAAIAAAAAA3wAAAAAA",
      "base64"
    ),
    // this is not multisig, which is not supported but the number of
    // partial signatures which is related to the number of inputs.
    num_signatures:1,
    navigation: [3, 0, 2, 0],
    // we split into 2 the snapshots navigation and comparision
    // this start valuo tells the navigateAndCompareUntilText method
    // from which image to start
    last: 6,
    hash: [ "8B6298B27F823219C62EDD33A03665EC51BBD470D27BAFF5F600E98188C075C3" ]
  },
  {
    name: 'psbt_4x3',
    op: Buffer.from(
      "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",
      "base64"
    ),
    num_signatures:4,
    // output 1 is marked as change, so only review 2.
    navigation: [3, 0,3, 0, 2, 0],
    // we split into 2 the snapshots navigation and comparision
    // this start valuo tells the navigateAndCompareUntilText method
    // from which image to start
    last: 10,
    hash: ["35AAE46FEF20A1175F35FCA2EC8CF947EF62DF9A4C0250DEF75F64F7BA436E02", "CE93F084BB8AD26273336D91E072CCED7DAA338116FC8F2E6861B104F6B9D67F", "2D01156B58C2E09A65B1518F03380FBF42A0E23353138380192387F114DE699E", "81055AB3375636DB0CB9630BD282E15E1A64708E61E5117FBACF4DC1E7C6767B"]
  },
]

function convert_der_to_rs(
    sig: Buffer,
): Buffer {
    const MINPAYLOADLEN = 1;
    const MAXPAYLOADLEN = 33;

    // let payload_range = core::ops::RangeInclusive::new(MINPAYLOADLEN, MAXPAYLOADLEN);
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
    if ( sig.length < 2 ) {
        throw new Error("wrong sig.length");
    }

    //check DER prefix
    if ( sig[0] != 0x30 ) {
        throw new Error("No DER sig");
    }

    //check payload len size
    const payload_len = sig[1];
    const min_payload_len = 2 + MINPAYLOADLEN + 2 + MINPAYLOADLEN;
    const max_payload_len = 2 + MAXPAYLOADLEN + 2 + MAXPAYLOADLEN;
    if ( payload_len < min_payload_len || payload_len > max_payload_len ) {
        throw new Error("wrong payload size");
    }

    //check that the input slice is at least as long as the encoded len
    if ( sig.length - 2 < payload_len ) {
        throw new Error("wrong payload size");
    }

    //retrieve R
    if ( sig[2] != 0x02 ) {
        throw new Error("wrong DER signature");
    }

    const r_len = sig[3];
    if ( r_len < MINPAYLOADLEN || r_len > MAXPAYLOADLEN) {
        throw new Error("wrong payload size");
    }

    const r = Buffer.from( sig.slice(4, 4 + r_len) );

    //retrieve S
    if ( sig[4 + r_len] != 0x02 ) {
        Buffer.alloc(0);

    }

    const s_len = sig[4 + r_len + 1];

    if ( s_len < MINPAYLOADLEN || s_len > MAXPAYLOADLEN) {
        throw new Error("wrong payload size");
    }

    const s = Buffer.from( sig.slice(4 + r_len + 2, 4+r_len + 2 + s_len) );
    var result = Buffer.concat([r, s])

    // remove 00 component from the begining of the signature,
    // the format of the der signature returned by btc app varies
    if (r[0] == 0 && result.length == 65){
        result = Buffer.from(result.slice(1))
    }

    return result
}

jest.setTimeout(300000)

describe.each(btc_models)('Psbt_[%s]; sign', function (m) {
  test.concurrent.each(BTC_DATA)('sign psbt $name', async function (obj) {
    const sim = new Zemu(m.path)

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const msg = obj.op

      const testcase = `${m.prefix.toLowerCase()}-sign-${obj.name}`

      const fpr = await app.getMasterFingerprint();
      console.log("Master key fingerprint:", fpr.toString());

      const xpub = await app.getBtcExtendedPubkey(BTC_PATH);
      console.log("Extended public key:", xpub.toString());

      // slice m/44'/60'/0' to /44'/60/..'
      const path = BTC_PATH.slice(1)

      const walletPolicy = new DefaultWalletPolicy(
        "wpkh(@0/**)",
        `[${fpr}${path}]${xpub}`
      );

      const psbt = new PsbtV2();
      psbt.deserialize(msg);
      const result = app.signPsbt(psbt, walletPolicy, null, () => {});

      // how is this going to work with our btc integration?
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      // skip the Processing... screen as it might/might not be added
      // this depends on transaction complexity and the time the app and client
      // takes to communicate and process data.
      await sim.waitForText("Review", 60000);

      await sim.navigate(".", testcase, obj.navigation);
      // It might happen that the last image is an Processing...
      // instead of Ready. so skip comparing the last image.
      // that does not mean something went wrong it is just how btc
      // app is designed.
      await sim.compareSnapshots(".", testcase, obj.last);

      const resp = await result

      expect(resp.length).toEqual(obj.num_signatures);
      console.log(JSON.stringify(resp))

      let signatureOks: { [index: string]: boolean } = {};

      for (var i = 0; i < obj.num_signatures; i++) {
        expect(resp[i][0]).toEqual(i);

        const signature = resp[i][1];

        const pk = Uint8Array.from(signature.pubkey)
        const signatureRS = convert_der_to_rs(signature.signature)
        const hash = Buffer.from(obj.hash[i], 'hex')

        console.log("signatureRS" + i+ ": ", signatureRS.toString('hex'))

        const signatureOk = secp256k1.ecdsaVerify(signatureRS, hash, pk)
        signatureOks[i] = signatureOk;
      }

      console.log(JSON.stringify(signatureOks))
      expect(Object.values(signatureOks).reduce((acc, x) => acc && x, true)).toEqual(true)

    } finally {
      await sim.close()
    }
  })
})

describe.each(btc_models)('btc_epubkey[%s]; sign', function (m) {
  test.concurrent('get extended public_key $name', async function () {
    const sim = new Zemu(m.path)

    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())

      const testcase = `${m.prefix.toLowerCase()}-btc_expub_key-${m.name}`

      const fpr = await app.getMasterFingerprint();
      console.log("Master key fingerprint:", fpr.toString());

      const xpub = app.getBtcExtendedPubkey(BTC_PATH, true);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.navigateAndCompareUntilText('.', testcase, "Approve")

      const extended_pubkey = await xpub
      console.log("Extended public key:", extended_pubkey);

      expect(extended_pubkey).toEqual(EXPECTED_EXTENDED_PUBKEY);

    } finally {
      await sim.close()
    }
  })
})

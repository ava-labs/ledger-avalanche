/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
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
 ******************************************************************************* */

import Zemu from '@zondax/zemu'
import { ETH_DERIVATION, defaultOptions, models, enableBlindSigning } from './common'
import Eth from '@ledgerhq/hw-app-eth'
import { ec } from 'elliptic'

const SIGN_TEST_DATA = [
  {
    name: 'transfer',
    op: Buffer.from(
      '02f5018402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c0',
      'hex',
    ),
  },
  {
   
    name: 'asset_transfer',
    op: Buffer.from(
      'f87c01856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef82a8688080',
      'hex',
    ),
  },
  {
    name: 'asset_deposit',
    op: Buffer.from(
      'f87c01856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef82a8688080',
      'hex',
    ),
  },
  {
    name: 'legacy_transfer',
    op: Buffer.from(
      'ed01856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080',
      'hex',
    ),
  },
]

describe.each(models)('EthereumTx [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign transaction:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Eth(sim.getTransport())
      const msg = data.op

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${data.name}`

      const currentScreen = sim.snapshot()

      const respReq = app.signTransaction(ETH_DERIVATION, msg.toString('hex'), null)
      await sim.waitUntilScreenIsNot(currentScreen, 20000)
      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, data.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      //Verify signature
     const resp_addr = await app.getAddress(ETH_DERIVATION, false)

      const EC = new ec("secp256k1");
      const sha3 = require('js-sha3');
      const msgHash = sha3.keccak256(msg);

      const pubKey = Buffer.from(resp_addr.publicKey, 'hex')
      const signature_obj = {
        r: Buffer.from(resp.r, 'hex'),
        s: Buffer.from(resp.s, 'hex'),
      }

      const signatureOK = EC.verify(msgHash, signature_obj, pubKey, 'hex')
      expect(signatureOK).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe.each(models)('EthereumKeys [%s] - pubkey', function (m) {
  test('get pubkey and addr %s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Eth(sim.getTransport())
      const resp = await app.getAddress(ETH_DERIVATION, false)

      console.log(resp, m.name)

      expect(resp).toHaveProperty('address')
      expect(resp).toHaveProperty('publicKey')
    } finally {
      await sim.close()
    }
  })

  test('show addr %s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Eth(sim.getTransport())
      const respReq = app.getAddress(ETH_DERIVATION, true)

      await sim.waitScreenChange()
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-eth-addr`)

      const resp = await respReq
      console.log(resp, m.name)

      expect(resp).toHaveProperty('publicKey')
      expect(resp).toHaveProperty('address')
    } finally {
      await sim.close()
    }
  })

  test('get xpub and addr %s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Eth(sim.getTransport())
      const resp = await app.getAddress(ETH_DERIVATION, false, true)

      console.log(resp, m.name)

      expect(resp).toHaveProperty('address')
      expect(resp).toHaveProperty('publicKey')
      expect(resp).toHaveProperty('chainCode')
      expect(resp.chainCode).not.toBeUndefined();
    } finally {
      await sim.close()
    }
  })
})

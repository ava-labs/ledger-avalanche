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

const secp256k1 = new ec('secp256k1')

const SIGN_TEST_DATA = [
  {
    name: 'blind sign',
    //ethereum tx hash: 0x7935135a927b1746b54e73c2b353daee96ba6aad6dd45683b36075b8092608fe
    op: Buffer.from(
      '02f878018402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c080a01e514f7fc78197c66589083cc8fd06376bae627a4080f5fb58d52d90c0df340da049b048717f215e622c93722ff5b1e38e1d1a4ab9e26a39183969a34a5f8dea75',
      'hex',
    ),
  },
]

describe.each(models)('Ethereum [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign operation', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Eth(sim.getTransport())
      const msg = data.op

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${data.name}`

      await enableBlindSigning(sim, testcase)
      const currentScreen = sim.snapshot()
      const respReq = app.signTransaction(ETH_DERIVATION, msg.toString('hex'))

      await sim.waitUntilScreenIsNot(currentScreen, 20000)
      await sim.navigateAndCompareUntilText('.', testcase, 'Approve')

      const resp = await respReq

      console.log(resp, m.name, data.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      const resp_addr = await app.getAddress(ETH_DERIVATION, false)
      const pkey = secp256k1.keyFromPublic(resp_addr.publicKey)

      // let signatureOK = pkey.verify(resp.hash, resp.signature)
      // expect(signatureOK).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

describe.each(models)('Ethereum [%s] - pubkey', function (m) {
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
      await sim.navigateAndCompareUntilText('.', `${m.prefix.toLowerCase()}-eth-addr`, 'Approve')

      const resp = await respReq
      console.log(resp, m.name)

      expect(resp).toHaveProperty('publicKey')
      expect(resp).toHaveProperty('address')
    } finally {
      await sim.close()
    }
  })
})

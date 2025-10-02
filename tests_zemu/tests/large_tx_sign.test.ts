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
import { ETH_DERIVATION, defaultOptions as commonOpts, defaultOptionsBlindSign, models } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import { large_tx } from './large_tx'
import { ec } from 'elliptic'

const defaultOptions = (model: any) => {
  let opts = commonOpts(model, false)
  return opts
}

const blindSignOptions = (model: any) => {
  return {
    ...defaultOptionsBlindSign,
    model: model.name,
  }
}

jest.setTimeout(60000)

describe.each(models)('LargeTx [%s]; blind signing', function (m) {
  test.concurrent('sign large transaction with blind signing enabled', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(blindSignOptions(m))
      const app = new AvalancheApp(sim.getTransport())

      // Enable blind signing
      await sim.toggleBlindSigning()

      const msg = large_tx
      const testcase = `${m.prefix.toLowerCase()}-eth-sign-large-tx-blindsign`

      const currentScreen = await sim.snapshot()

      const respReq = app.signEVMTransaction(ETH_DERIVATION, msg.toString('hex'))
      await sim.waitUntilScreenIsNot(currentScreen, 100000)
      await sim.compareSnapshotsAndApprove('.', testcase, true, 0, 1500, true)

      const resp = await respReq

      console.log('Signature response:', resp, m.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      // Verify signature
      const resp_addr = await app.getETHAddress(ETH_DERIVATION, false)

      const EC = new ec('secp256k1')
      const sha3 = require('js-sha3')
      const msgHash = sha3.keccak256(msg)

      const pubKey = Buffer.from(resp_addr.publicKey, 'hex')
      const signature_obj = {
        r: Buffer.from(resp.r, 'hex'),
        s: Buffer.from(resp.s, 'hex'),
      }

      const ok = EC.verify(msgHash, signature_obj, pubKey, 'hex')
      expect(ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

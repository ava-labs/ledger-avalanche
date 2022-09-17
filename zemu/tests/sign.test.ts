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
import { APP_DERIVATION, ETH_DERIVATION, defaultOptions, models, enableBlindSigning, ROOT_PATH } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'

const SIGN_TEST_DATA = [
  {
    name: 'blind sign',
    op: Buffer.from('hello@zondax.ch'),
  },
]

describe.skip.each(models)('Standard [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('$name operation', async function ({ name, op }) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const msg = op

      const testcase = `${m.prefix.toLowerCase()}-sign-${name}`
      await enableBlindSigning(sim, testcase)

      const currentScreen = sim.snapshot();
      const signers = ["0/1", "5/8"];
      const respReq = app.sign(ROOT_PATH, signers, msg);

      await sim.waitUntilScreenIsNot(currentScreen, 20000)

      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')

      const hash = crypto.createHash('sha256')
      const msgHash = Uint8Array.from(hash.update(msg).digest())

      for (const signer of signers) {
        const path = `${ROOT_PATH}/${signer}`
        const resp_addr = await app.getAddressAndPubKey(path, false)
        const pk = Uint8Array.from(resp_addr.publicKey)
        const signatureRS = Uint8Array.from(resp.signatures?.get(signer)!).slice(0, -1)

        const signatureOk = secp256k1.ecdsaVerify(signatureRS, msgHash, pk)
        expect(signatureOk).toEqual(true)
      }

    } finally {
      await sim.close()
    }
  })
})

describe.skip.each(models)('Ethereum [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('$name operation', async function ({ name, op }) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const msg = op

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${name}`
      await enableBlindSigning(sim, testcase)

      const currentScreen = sim.snapshot();
      const signers = ["0/1"];
      const respReq = app.sign(ETH_DERIVATION, signers, msg);

      await sim.waitUntilScreenIsNot(currentScreen, 20000)
      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')

      const resp_addr = await app.getAddressAndPubKey(ETH_DERIVATION, false)

      const signatureRS = resp.signatures?.get(signers[0])!.slice(0, -1)

      const signatureOk = secp256k1.ecdsaVerify(signatureRS, resp.hash, resp_addr.publicKey)
      expect(signatureOk).toEqual(true)

    } finally {
      await sim.close()
    }
  })
})

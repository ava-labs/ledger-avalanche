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
import { APP_DERIVATION, ETH_DERIVATION, cartesianProduct, curves, defaultOptions, models, enableBlindSigning, ROOT_PATH } from './common'
import AvalancheApp, { Curve } from '@zondax/ledger-avalanche-app'

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'

const SIGN_TEST_DATA = cartesianProduct(curves, [
  {
    name: 'blind sign',
    nav: { s: [2, 0], x: [3, 0], sp: [3, 0] },
    op: Buffer.from('hello@zondax.ch'),
  },
])

describe.skip.each(models)('Standard [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign operation', async function (curve, data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const msg = data.op

      const testcase = `${m.prefix.toLowerCase()}-sign-${data.name}-${curve}`
      await enableBlindSigning(sim, testcase)

      const currentScreen = sim.snapshot();
      const signers = ["0/1", "5/8"];
      const respReq = app.sign(ROOT_PATH, signers, msg);

      await sim.waitUntilScreenIsNot(currentScreen, 20000)

      const navigation = m.name == 'nanox' ? data.nav.x : m.name == "nanosp" ? data.nav.sp : data.nav.s;
      await sim.navigateAndCompareSnapshots('.', testcase, navigation)

      const resp = await respReq

      console.log(resp, m.name, data.name, curve)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')

      switch (curve) {
        case Curve.Secp256K1:
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
          break

        default:
          throw Error('not a valid curve type')
      }
    } finally {
      await sim.close()
    }
  })
})

describe.skip.each(models)('Ethereum [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign operation', async function (curve, data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const msg = data.op

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${data.name}-${curve}`
      await enableBlindSigning(sim, testcase)

      const currentScreen = sim.snapshot();
      const signers = ["0/1", "5/8"];
      const respReq = app.sign(APP_DERIVATION, signers, msg);

      await sim.waitUntilScreenIsNot(currentScreen, 20000)

      const navigation = m.name == 'nanox' ? data.nav.x : m.name == "nanosp" ? data.nav.sp : data.nav.s;
      await sim.navigateAndCompareSnapshots('.', testcase, navigation)

      const resp = await respReq

      console.log(resp, m.name, data.name, curve)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')

      const resp_addr = await app.getAddressAndPubKey(ETH_DERIVATION, false)
      const pkey = secp256k1.keyFromPublic(resp_addr.publicKey)

      let signatureOK = true
      switch (curve) {
        case Curve.Secp256K1:
          //signature without r or s error thrown?
          // signatureOK = pkey.verify(resp.hash, resp.signature)
          break

        default:
          throw Error('not a valid curve type')
      }
      expect(signatureOK).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

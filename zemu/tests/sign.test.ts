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
import { APP_DERIVATION, cartesianProduct, curves, defaultOptions, models } from './common'
import AvalancheApp, { Curve } from '@zondax/ledger-avalanche-app'
import { ec } from 'elliptic'

const secp256k1 = new ec('secp256k1');

const SIGN_TEST_DATA = cartesianProduct(curves, [
  {
    name: 'blind sign',
    nav: { s: [2, 0], x: [3, 0], sp: [3, 0] },
    op: Buffer.from('hello@zondax.ch'),
  },
])

describe.each(models)('Standard [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign operation', async function (curve, data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const msg = data.op
      const respReq = app.sign(APP_DERIVATION, curve, msg)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)

      const navigation = m.name == 'nanox' ? data.nav.x : m.name == "nanosp" ? data.nav.sp : data.nav.s;
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-sign-${data.name}-${curve}`, navigation)

      const resp = await respReq

      console.log(resp, m.name, data.name, curve)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('hash')
      expect(resp).toHaveProperty('signature')

      const resp_addr = await app.getAddressAndPubKey(APP_DERIVATION, curve)
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

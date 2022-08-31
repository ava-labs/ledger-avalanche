/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
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
import { APP_DERIVATION, ETH_DERIVATION, cartesianProduct, curves, defaultOptions, models, enableBlindSigning } from './common'
import AvalancheApp, { Curve } from '@zondax/ledger-avalanche-app'
import { ec } from 'elliptic'
import { C_IMPORT_FROM_X, C_EXPORT_TO_X} from './c_chain_vectors'

const secp256k1 = new ec('secp256k1');

const SIGN_TEST_DATA = cartesianProduct(curves, [
  {
    name: 'c_import_from_x',
    op: C_IMPORT_FROM_X ,
  },
  {
    name: 'c_export_to_x',
    op: C_EXPORT_TO_X,
  },
])

describe.each(models)('Standard [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign c-chain transactions', async function (curve, data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const msg = data.op

      const testcase = `${m.prefix.toLowerCase()}-sign-${data.name}-${curve}`

      const signers = ["0/1", "5/8"];
      const respReq = app.sign(APP_DERIVATION, signers, msg);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, data.name, curve)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')
      expect(resp.signatures?.size).toEqual(signers.length)

    } finally {
      await sim.close()
    }
  })
})


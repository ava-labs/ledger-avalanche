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
import { ROOT_PATH, cartesianProduct, defaultOptions, models } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import { X_IMPORT_FROM_P, X_EXPORT_TO_C, X_CREATE_ASSET, X_OPERATION } from './x_chain_vectors'

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'

const LITE_SIGN_TEST_DATA = [
  {
    name: 'x_import_from_p',
    op: X_IMPORT_FROM_P,
  },
  {
    name: 'x_export_to_c',
    op: X_EXPORT_TO_C,
  },
  {
    name: 'x_operation',
    op: X_OPERATION,
  },
]

const FULL_SIGN_TEST_DATA = [
  {
    name: 'x_create_asset',
    op: X_CREATE_ASSET,
  },
]

describe.each(models)('X_Sign[%s]; sign', function (m) {
  test.concurrent.each(FULL_SIGN_TEST_DATA)('[full] sign x-chain $name', async function ({ name, op }) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())
      const msg = op

      const testcase = `${m.prefix.toLowerCase()}-sign-${name}`

      const signers = ["0/1", "5/8"];
      const respReq = app.sign(ROOT_PATH, signers, msg);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')
      expect(resp.signatures?.size).toEqual(signers.length)

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

  test.concurrent.each(LITE_SIGN_TEST_DATA)('sign x-chain $name', async function ({ name, op }) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())
      const msg = op

      const testcase = `${m.prefix.toLowerCase()}-sign-${name}`

      const signers = ["0/1", "5/8"];
      const respReq = app.sign(ROOT_PATH, signers, msg);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')
      expect(resp.signatures?.size).toEqual(signers.length)

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


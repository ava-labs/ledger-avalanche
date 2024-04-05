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
import { defaultOptions, models, ROOT_PATH } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import {
  ADD_VALIDATOR_DATA,
  ADD_DELEGATOR_DATA,
  ADD_SUBNET_VALIDATOR_DATA,
  P_IMPORT_FROM_X,
  P_EXPORT_TO_X,
  CREATE_SUBNET,
  CREATE_CHAIN,
  ADD_PERMISSIONLESS_DELEGATOR,
  ADD_PERMISSIONLESS_VALIDATOR,
  ADD_SUBNET_PERMISSIONLESS_DELEGATOR,
  ADD_SUBNET_PERMISSIONLESS_VALIDATOR,
  TRANSFORM_SUBNET,
  REMOVE_SUBNET_VALIDATOR,
} from './p_chain_vectors'

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'

jest.setTimeout(200000)

const LITE_SIGN_TEST_DATA = [
  {
    name: 'p_import_from_x',
    op: P_IMPORT_FROM_X,
  },
  {
    name: 'p_export_to_x',
    op: P_EXPORT_TO_X,
  },
  {
    name: 'add_validator',
    op: ADD_VALIDATOR_DATA,
  },
  {
    name: 'add_delegator',
    op: ADD_DELEGATOR_DATA,
  },
]

const FULL_SIGN_TEST_DATA = [
  {
    name: 'add_subnet_validator',
    op: ADD_SUBNET_VALIDATOR_DATA,
  },
  {
    name: 'create_subnet',
    op: CREATE_SUBNET,
  },
  {
    name: 'create_chain',
    op: CREATE_CHAIN,
  },
  {
    name: 'add_permissionless_delegator',
    op: ADD_PERMISSIONLESS_DELEGATOR,
  },
  {
    name: 'add_permissionless_validator',
    op: ADD_PERMISSIONLESS_VALIDATOR,
  },
  {
    name: 'add_subnet_permissionless_delegator',
    op: ADD_SUBNET_PERMISSIONLESS_DELEGATOR,
  },
  {
    name: 'add_subnet_permissionless_validator',
    op: ADD_SUBNET_PERMISSIONLESS_VALIDATOR,
  },
  {
    name: 'transform_subnet',
    op: TRANSFORM_SUBNET,
  },
  {
    name: 'remove_subnet_validator',
    op: REMOVE_SUBNET_VALIDATOR,
  },
]

describe.each(models)('P_Sign[$name]; sign', function (m) {
  test.concurrent.each(FULL_SIGN_TEST_DATA)('[full] sign p-chain $name', async function ({ name, op }) {
    const sim = new Zemu(m.path)

    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())
      const msg = op

      const testcase = `${m.prefix.toLowerCase()}-sign-${name}`

      const signers = ['0/0', '0/1', '1/100']
      const respReq = app.sign(ROOT_PATH, signers, msg)

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

      let signatureOks: { [index: string]: boolean } = {}
      for (const signer of signers) {
        const path = `${ROOT_PATH}/${signer}`
        const resp_addr = await app.getAddressAndPubKey(path, false)
        const pk = Uint8Array.from(resp_addr.publicKey)
        const signatureRS = Uint8Array.from(resp.signatures?.get(signer)!).slice(0, -1)

        const signatureOk = secp256k1.ecdsaVerify(signatureRS, msgHash, pk)
        signatureOks[signer] = signatureOk
      }

      console.log(JSON.stringify(signatureOks))
      expect(Object.values(signatureOks).reduce((acc, x) => acc && x, true)).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(LITE_SIGN_TEST_DATA)('sign p-chain $name', async function ({ name, op }) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())
      const msg = op

      const testcase = `${m.prefix.toLowerCase()}-sign-${name}`

      const signers = ['0/0', '0/1', '1/100']
      const respReq = app.sign(ROOT_PATH, signers, msg)

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

      let signatureOks: { [index: string]: boolean } = {}
      for (const signer of signers) {
        const path = `${ROOT_PATH}/${signer}`
        const resp_addr = await app.getAddressAndPubKey(path, false)
        const pk = Uint8Array.from(resp_addr.publicKey)
        const signatureRS = Uint8Array.from(resp.signatures?.get(signer)!).slice(0, -1)

        const signatureOk = secp256k1.ecdsaVerify(signatureRS, msgHash, pk)
        signatureOks[signer] = signatureOk
      }

      console.log(JSON.stringify(signatureOks))
      expect(Object.values(signatureOks).reduce((acc, x) => acc && x, true)).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

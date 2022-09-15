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
import { ROOT_PATH, cartesianProduct, curves, defaultOptions, models } from './common'
import AvalancheApp, { Curve } from '@zondax/ledger-avalanche-app'
import { SIMPLE_TRANSFER_DATA } from './common_sign_vectors'

const sha256 = require('js-sha256').sha256

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'

const SIGN_TEST_DATA = cartesianProduct(curves, [
  {
    name: 'simple_transfer',
    op: SIMPLE_TRANSFER_DATA ,
    filter: false,
  },
  // {
  //   name: 'simple_transfer_hide_output',
  //   op: SIMPLE_TRANSFER_DATA ,
  //   filter: true,
  // },
])

describe.each(models)('Transfer [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign basic transactions', async function (curve, data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const msg = data.op

      const testcase = `${m.prefix.toLowerCase()}-sign-${data.name}-${curve}`

      const currentScreen = sim.snapshot();
      const signers = ["0/0", "5/8"];
      let change_path = undefined
      if (data.filter === true) {
        change_path = ["0/1", "1/100" ];
      }
      const respReq = app.sign(ROOT_PATH, signers, msg, change_path);

      await sim.waitUntilScreenIsNot(currentScreen, 20000)

      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, data.name, curve)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')
      expect(resp.signatures?.size).toEqual(signers.length)

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

describe.each(models)('signHash [%s]', function (m) {
  test.each(curves)('sign hash', async function (curve) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const message = "AvalancheApp"
      const msg = Buffer.from(sha256(message), "hex");

      const testcase = `${m.prefix.toLowerCase()}-sign-hash-${curve}`

      const signing_list = ["0/0", "4/8"];
      const respReq = app.signHash(ROOT_PATH, signing_list, msg);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', testcase)


      const resp = await respReq

      console.log(resp, m.name, "signHash", curve)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')
      expect(resp.signatures?.size).toEqual(signing_list.length)

      for (const signer of signing_list) {
        const path = `${ROOT_PATH}/${signer}`
        const resp_addr = await app.getAddressAndPubKey(path, false)
        const pk = Uint8Array.from(resp_addr.publicKey)
        const signatureRS = Uint8Array.from(resp.signatures?.get(signer)!).slice(0, -1)

        const signatureOk = secp256k1.ecdsaVerify(signatureRS, msg, pk)
        expect(signatureOk).toEqual(true)
      }

    } finally {
      await sim.close()
    }
  })

  test.each(curves)('signMsg', async function (curve) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new AvalancheApp(sim.getTransport())
      const message = "Welcome to OpenSea!\n\nClick to sign in and accept the OpenSea Terms of Service: https://opensea.io/tos\n\nThis request will not trigger a blockchain transaction or cost any gas fees.\n\nYour authentication status will reset after 24 hours.\n\nWallet address:\n0x9858effd232b4033e47d90003d41ec34ecaeda94\n\nNonce:\n2b02c8a0-f74f-4554-9821-a28054dc9121";

      const testcase = `${m.prefix.toLowerCase()}-sign-msg-${curve}`

      const signing_list = ["0/0", "4/8"];
      const respReq = app.signMsg(ROOT_PATH, signing_list, message);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, "signMsg", curve)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')
      expect(resp.signatures?.size).toEqual(signing_list.length)

      const hash = crypto.createHash('sha256')
      const header = Buffer.from("\x1AAvalanche Signed Message:\n", 'utf8');
      const content = Buffer.from(message, 'utf8')
      let msgSize = Buffer.alloc(4)
      msgSize.writeUInt32BE(content.length, 0)
      const avax_msg = Buffer.from(`${header}${msgSize}${content}`, 'utf8')
      const msgHash = Uint8Array.from(hash.update(avax_msg).digest())

      for (const signer of signing_list) {
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


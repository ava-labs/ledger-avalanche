/** ******************************************************************************
 *  (c) 2023 Zondax AG
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
import { ETH_DERIVATION, defaultOptions as commonOpts, models } from './common'
import Eth from '@ledgerhq/hw-app-eth'

const defaultOptions = (model: any) => {
  return commonOpts(model, true)
}

describe.each(models)('EthereumKeys [%s] - pubkey', function (m) {
  test.concurrent('get pubkey and addr %s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new Eth(sim.getTransport())

      const ETH_PATH = "m/44'/60'/0'/0'/5"
      const EXPECTED_PUBLIC_KEY = '024f1dd50f180bfd546339e75410b127331469837fa618d950f7cfb8be351b0020';
      const resp = await app.getAddress(ETH_PATH, false)

      console.log(resp, m.name)

      expect(resp).toHaveProperty('address')
      expect(resp).toHaveProperty('publicKey')
      expect(resp.publicKey === EXPECTED_PUBLIC_KEY)
    } finally {
      await sim.close()
    }
  })

  test.concurrent('show addr %s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new Eth(sim.getTransport())
      const respReq = app.getAddress(ETH_DERIVATION, true)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-eth-addr`)

      const resp = await respReq
      console.log(resp, m.name)

      expect(resp).toHaveProperty('publicKey')
      expect(resp).toHaveProperty('address')
    } finally {
      await sim.close()
    }
  })

  test.concurrent('get xpub and addr %s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
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

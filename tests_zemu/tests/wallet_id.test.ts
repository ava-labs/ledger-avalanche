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
import { defaultOptions, models } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'

jest.setTimeout(200000)

describe.each(models)('WalletID [%s] - wallet id', function (m) {
  test.concurrent('getWalletId', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())
      const resp = await app.getWalletId()

      console.log(resp, m.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('id')
    } finally {
      await sim.close()
    }
  })

  test.concurrent('showWalletId', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m, true))
      const app = new AvalancheApp(sim.getTransport())
      const respReq = app.showWalletId()

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-wallet-id`)

      const resp = await respReq
      console.log(resp, m.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('id')
    } finally {
      await sim.close()
    }
  })
})
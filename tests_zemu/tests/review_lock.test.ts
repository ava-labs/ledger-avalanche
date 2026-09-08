/** ******************************************************************************
 *  (c) 2026 Zondax GmbH
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

import Zemu, { ButtonKind, TouchNavigation, isTouchDevice } from '@zondax/zemu'
import AvalancheApp, { LedgerError } from '@zondax/ledger-avalanche-app'
import { ROOT_PATH, defaultOptions, models } from './common'

const sha256 = require('js-sha256').sha256

const REVIEW_LOCK_MODELS = models.filter(({ name }) => name === 'nanox' || name === 'stax')

const rejectCurrentReview = async (sim: Zemu, model: (typeof models)[number]) => {
  if (!isTouchDevice(model.name)) {
    await sim.navigateUntilText('.', 'unused', 'REJECT', true, false)
    return
  }

  await sim.navigateUntilText('.', 'unused', 'Cancel', true, false, 0, 15000, false)
  const nav = new TouchNavigation(model.name, [ButtonKind.RejectButton, ButtonKind.ConfirmYesButton])
  await sim.navigate('.', 'unused', nav.schedule, true, false)
}

jest.setTimeout(200000)

describe.each(REVIEW_LOCK_MODELS)('review lock [%s]', function (m) {
  test('rejects repeated APDUs without releasing the active review', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())
      const hash = Buffer.from(sha256('Avalanche review lock'), 'hex')

      const reviewRequest = app.signHash(ROOT_PATH, ['0/0'], hash)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      for (let attempt = 0; attempt < 2; attempt += 1) {
        await expect(sim.getTransport().send(0x80, 0x00, 0x00, 0x00)).rejects.toMatchObject({
          statusCode: LedgerError.TransactionRejected,
        })
      }

      await rejectCurrentReview(sim, m)
      const rejection = await reviewRequest
      expect(rejection.returnCode).toEqual(LedgerError.TransactionRejected)

      const version = await app.getVersion()
      expect(version.returnCode).toEqual(LedgerError.NoErrors)
    } finally {
      await sim.close()
    }
  })
})

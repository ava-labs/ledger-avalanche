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
import { curves, defaultOptions, models } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'

const APP_DERIVATION = "m/44'/9000'/0'"
const ETH_DERIVATION = "m/44'/60'/0'"

describe.each(models)('Standard [%s] - extended pubkey', function (m) {
  test.each(curves)(
    'get pubkey %s',
    async function (curve) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        const app = new AvalancheApp(sim.getTransport())
        const resp = await app.getExtendedPubKey(APP_DERIVATION, false)

        console.log(resp, m.name)

        expect(resp.returnCode).toEqual(0x9000)
        expect(resp.errorMessage).toEqual('No errors')
        expect(resp).toHaveProperty('publicKey')
        expect(resp).toHaveProperty('chain_code')
      } finally {
        await sim.close()
      }
    },
  );

  test.each(curves)(
    'show addr %s',
    async function (curve) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        const app = new AvalancheApp(sim.getTransport())
        const respReq = app.getExtendedPubKey(APP_DERIVATION, true)

        await sim.waitScreenChange();

        const navigation = m.name == 'nanos' ? 3 : 4;
        await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-xpub-${curve}`, navigation);

        const resp = await respReq;
        console.log(resp, m.name)

        expect(resp.returnCode).toEqual(0x9000)
        expect(resp.errorMessage).toEqual('No errors')
        expect(resp).toHaveProperty('publicKey')
        expect(resp).toHaveProperty('chain_code')
      } finally {
        await sim.close()
      }
    },
  );
})

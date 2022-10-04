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
import { APP_DERIVATION, defaultOptions, models } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import { encode as bs58_encode } from 'bs58'

const EXPECTED_PUBLIC_KEY = '02c6f477ff8e7136de982f898f6bfe93136bbe8dada6c17d0cd369acce90036ac4';

describe.each(models)('Standard [%s] - pubkey', function (m) {
  test(
    'get pubkey and addr',
    async function () {
      const sim = new Zemu(m.path)
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        const app = new AvalancheApp(sim.getTransport())
        const resp = await app.getAddressAndPubKey(APP_DERIVATION, false)

        console.log(resp, m.name)

        expect(resp.returnCode).toEqual(0x9000)
        expect(resp.errorMessage).toEqual('No errors')
        expect(resp).toHaveProperty('publicKey')
        expect(resp).toHaveProperty('hash')
        expect(resp.publicKey.toString('hex')).toEqual(EXPECTED_PUBLIC_KEY)
      } finally {
        await sim.close()
      }
    },
  );

  test(
    'show addr',
    async function () {
      const sim = new Zemu(m.path)
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        const app = new AvalancheApp(sim.getTransport())
        const respReq = app.getAddressAndPubKey(APP_DERIVATION, true)

        await sim.waitScreenChange();

        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-addr`);

        const resp = await respReq;
        console.log(resp, m.name)

        expect(resp.returnCode).toEqual(0x9000)
        expect(resp.errorMessage).toEqual('No errors')
        expect(resp).toHaveProperty('publicKey')
        expect(resp).toHaveProperty('hash')
      } finally {
        await sim.close()
      }
    },
  );

  test(
    'show custom hrp & chainID addr',
    async function () {
      const sim = new Zemu(m.path)
      try {
        await sim.start({ ...defaultOptions, model: m.name })
        const app = new AvalancheApp(sim.getTransport())
        const respReq = app.getAddressAndPubKey(APP_DERIVATION, true,
          "zemu", bs58_encode(Buffer.alloc(32, 42)))

        await sim.waitScreenChange();

        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-zemu-addr`);

        const resp = await respReq;
        console.log(resp, m.name)

        expect(resp.returnCode).toEqual(0x9000)
        expect(resp.errorMessage).toEqual('No errors')
        expect(resp).toHaveProperty('publicKey')
        expect(resp).toHaveProperty('hash')
      } finally {
        await sim.close()
      }
    },
  );
})

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
import { ETH_DERIVATION, defaultOptions as commonOpts, models } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'

import { LegacyTransaction } from '@ethereumjs/tx'
import { Common } from '@ethereumjs/common'
import { RLP } from '@ethereumjs/rlp'
// import { ec } from 'elliptic'

const defaultOptions = (model: any) => {
  let opts = commonOpts(model, false)
  return opts
}

jest.setTimeout(90000)

// type NftInfo = {
//   token_address: string
//   token_name: string
//   chain_id: number
// }

type Op = {
  to?: string
  value?: string
  data?: string
}
type TestData = {
  name: string
  op: Op
  // nft_info?: NftInfo
  chainId?: number
}
const SIGN_TEST_DATA: TestData[] = [
  {
    name: 'basic_transfer',
    op: {
      value: 'abcdef00',
      to: 'df073477da421520cf03af261b782282c304ad66',
    },
    chainId: 2,
  },
  {
    name: 'legacy_contract_deploy',
    op: {
      value: 'abcdef00',
      data: '1a8451e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    },
    chainId: 5,
  },
  {
    name: 'legacy_contract_call',
    op: {
      to: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
      value: 'abcdef01',
      data: 'ee919d500000000000000000000000000000000000000000000000000000000000000001',
    },
    chainId: 689,
  },
  {
    name: 'basic_transfer_no_eip155',
    op: {
      value: 'a1bcd400',
      to: 'df073477da421520cf03af261b782282c304ad66',
    },
  },
  {
    name: 'contract_deploy_no_eip155',
    op: {
      value: '1',
      data: '1a8451e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    },
  },
]

const rawUnsignedLegacyTransaction = (params: Op, chainId?: number) => {
  const txParams = {
    nonce: BigInt(0),
    gasPrice: BigInt('0x6d6e2edc00'),
    gasLimit: BigInt('0x2dc6c0'),
    to: params.to !== undefined ? Buffer.from(params.to, 'hex') : undefined,
    value: BigInt('0x' + params.value),
    data: params.data !== undefined ? Buffer.from(params.data, 'hex') : undefined,
  }

  const chain = Common.custom({
    name: 'avalanche',
    networkId: chainId || 2,
    chainId: chainId || 2,
  })

  const options = { common: chain }

  // legacy
  const tx = LegacyTransaction.fromTxData(txParams, options)

  let unsignedTx = tx.getMessageToSign()
  return new Uint8Array(RLP.encode(unsignedTx))
}

// an alternative verification method for legacy transactions, taken from obsidian
// which uses the ethereumIS library
function check_legacy_signature(hexTx: string, signature: any, chainId: number | undefined) {
  const ethTx = Buffer.from(hexTx, 'hex')

  const chain = Common.custom({
    name: 'avalanche',
    networkId: chainId || 2, // Use passed chainId or default to 1
    chainId: chainId || 2, // This should be set according to the passed chainId
  })

  const tx_options = { common: chain }

  const txnBufsDecoded: any = RLP.decode(ethTx).slice(0, 6)
  const txnBufsMap = [signature.v, signature.r, signature.s].map(a => Buffer.from(a.length % 2 == 1 ? '0' + a : a, 'hex'))

  const txnBufs = txnBufsDecoded.concat(txnBufsMap)

  const ethTxObj = LegacyTransaction.fromValuesArray(txnBufs, tx_options)

  return ethTxObj.verifySignature()
}

describe.each(models)('EthereumLegacy [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign legacy:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))

      const app = new AvalancheApp(sim.getTransport())

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${data.name}`

      const currentScreen = await sim.snapshot()
      const msg = rawUnsignedLegacyTransaction(data.op, data.chainId)

      const respReq = app.signEVMTransaction(ETH_DERIVATION, Buffer.from(msg).toString('hex'), null)
      await sim.waitUntilScreenIsNot(currentScreen, 60000)

      await sim.compareSnapshotsAndApprove('.', `${testcase}`)

      const resp = await respReq

      console.log(resp, m.name, data.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      const test = check_legacy_signature(Buffer.from(msg).toString('hex'), resp, data.chainId)
      expect(test).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

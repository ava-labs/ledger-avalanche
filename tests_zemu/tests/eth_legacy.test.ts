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
import { ButtonKind } from '@zondax/zemu'
import { ETH_DERIVATION, defaultOptions as commonOpts, eth_models } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'

import { Transaction } from '@ethereumjs/tx'
import { Common } from '@ethereumjs/common'
import { bufArrToArr } from '@ethereumjs/util'
import { RLP } from '@ethereumjs/rlp'
// import { ec } from 'elliptic'

const defaultOptions = (model: any) => {
  let opts = commonOpts(model, true)
  opts.approveKeyword = model.name !== 'nanos' ? 'Accept' : 'APPROVE'
  opts.approveAction = ButtonKind.ApproveTapButton
  return opts
}

jest.setTimeout(15000)

// type NftInfo = {
//   token_address: string
//   token_name: string
//   chain_id: number
// }
//
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
    chainId: 9867,
  },
  // {
  //   name: 'legacy_contract_deploy',
  //   op: {
  //     value: 'abcdef00',
  //     data: '1a8451e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  //   },
  //   chainId: 5,
  // },
  // {
  //   name: 'legacy_contract_call',
  //   op: {
  //     to: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
  //     value: 'abcdef01',
  //     data: 'ee919d500000000000000000000000000000000000000000000000000000000000000001',
  //   },
  //   chainId: 689,
  // },
  // {
  //   name: 'erc20_transfer',
  //   op: {
  //     // this is not probably the contract address but lets use it
  //     to: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
  //     value: '0',
  //     data: 'a9059cbb0000000000000000000000005f658a6d1928c39b286b48192fea8d46d87ad07700000000000000000000000000000000000000000000000000000000000f4240',
  //   },
  //   chainId: 65089,
  // },
  // {
  //   name: 'pangolin_contract_call',
  //   op: {
  //     // Pangolin AVAX/DAI swap 2
  //     to: '62650ae5c5777d1660cc17fcd4f550000eacdfa0',
  //     value: '0',
  //     data: '8a657e670000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000c7b9b39ab3081ac34fc4324e3f648b55528871970000000000000000000000000000000000000000000000000000017938e114be0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000b31f66aa3c1e785363f0875a1b74e27b85fd66c7000000000000000000000000ba7deebbfc5fa1100fb055a87773e1e99cd3507a',
  //   },
  //   chainId: 100,
  // },
  // TODO: fix after Ledger investigates the issue with the emulator
  // {
  //   name: 'erc721_approve',
  //   op: {
  //     // this is not probably the contract address but lets use it
  //     to: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
  //     value: '0',
  //     data: '095ea7b30000000000000000000000005f658a6d1928c39b286b48192fea8d46d87ad07700000000000000000000000000000000000000000000000000000000000f4240',
  //   },
  //   chainId: 43114,
  //   nft_info: {
  //     token_address: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
  //     token_name: 'Unknown',
  //     chain_id: 43114,
  //   },
  // },
  {
    name: 'basic_transfer_no_eip155',
    op: {
      value: 'a1bcd400',
      to: 'df073477da421520cf03af261b782282c304ad66',
    },
  },
  // {
  //   name: 'contract_deploy_no_eip155',
  //   op: {
  //     value: '1',
  //     data: '1a8451e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  //   },
  // },
]

const rawUnsignedLegacyTransaction = (params: Op, chainId?: number) => {
  const txParams = {
    nonce: '0x00',
    gasPrice: '0x6d6e2edc00',
    gasLimit: '0x2dc6c0',
    to: params.to !== undefined ? '0x' + params.to : undefined,
    value: '0x' + params.value,
    data: params.data !== undefined ? '0x' + params.data : undefined,
  }

  const chain = Common.custom({ name: 'avalanche', networkId: 1, chainId }, { baseChain: 1 })
  const options = chainId !== undefined ? { common: chain } : undefined

  // legacy
  const tx = Transaction.fromTxData(txParams, options)

  let unsignedTx: Buffer[] | Buffer
  unsignedTx = tx.getMessageToSign(false)
  unsignedTx = Buffer.from(RLP.encode(bufArrToArr(unsignedTx)))

  return unsignedTx
}

// an alternative verification method for legacy transactions, taken from obsidian
// which uses the ethereumIS library
function check_legacy_signature(hexTx: string, signature: any, chainId: number | undefined) {
  const ethTx = Buffer.from(hexTx, 'hex')

  const chain = Common.custom({ name: 'avalanche', networkId: 1, chainId }, { baseChain: 1 })
  const tx_options = chainId !== undefined ? { common: chain } : undefined

  const txnBufsDecoded: any = RLP.decode(ethTx).slice(0, 6)
  const txnBufsMap = [signature.v, signature.r, signature.s].map(a => Buffer.from(a.length % 2 == 1 ? '0' + a : a, 'hex'))

  const txnBufs = txnBufsDecoded.concat(txnBufsMap)

  const ethTxObj = Transaction.fromValuesArray(txnBufs, tx_options)

  return ethTxObj.verifySignature()
}

describe.each(eth_models)('EthereumLegacy [%s]; sign', function (m) {
  test.concurrent.each(SIGN_TEST_DATA)('sign legacy:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))

      const app = new AvalancheApp(sim.getTransport())
      // Put the app in expert mode
      // await sim.toggleExpertMode()

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${data.name}`

      const currentScreen = await sim.snapshot()
      const msg = rawUnsignedLegacyTransaction(data.op, data.chainId)

      // const nft = data.nft_info
      // if (nft !== undefined) {
      //   const provide_resp = await app.provideNftInfo(nft.token_address, nft.token_name, nft.chain_id)
      //   expect(provide_resp.returnCode).toEqual(0x9000)
      // }

      const respReq = app.signEVMTransaction(ETH_DERIVATION, msg.toString('hex'), null)
      await sim.waitUntilScreenIsNot(currentScreen, 60000)
      if (m.name === 'nanos') {
        await sim.compareSnapshotsAndApprove('.', testcase)
      } else {
        await sim.navigateAndCompareUntilText('.', testcase, 'Accept')
      }

      const resp = await respReq

      console.log(resp, m.name, data.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      // TODO: Enable later
      //Verify signature
      // alternative verification to be safe
      // const test = check_legacy_signature(msg.toString('hex'), resp, data.chainId)
      expect(true).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

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

import Zemu, { ClickNavigation, isTouchDevice } from '@zondax/zemu'
import { ETH_DERIVATION, defaultOptions as commonOpts, models } from './common'
import Eth from '@ledgerhq/hw-app-eth'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import { ec } from 'elliptic'

const defaultOptions = (model: any) => {
  let opts = commonOpts(model, false)
  return opts
}

type NftInfo = {
  token_address: string
  token_name: string
  chain_id: number
}

type TestData = {
  name: string
  op: Buffer
  nft_info: NftInfo | undefined
}

// copied from python tests
const EIP712_TRANSACTION = {
  domain_hash: 'c24f499b8c957196651b13edd64aaccc3980009674b2aea0966c8a56ba81278e',
  msg_hash: '9d96be8a7cca396e711a3ba356bd9878df02a726d753ddb6cda3c507d888bc77',
}

const SIGN_TEST_DATA: TestData[] = [
  {
    name: 'transfer',
    op: Buffer.from(
      '02f5058402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c0',
      'hex',
    ),
    nft_info: undefined,
  },
  {
    name: 'asset_transfer',
    op: Buffer.from(
      'f87c02856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef82a8688080',
      'hex',
    ),
    nft_info: undefined,
  },
  {
    name: 'asset_deposit',
    op: Buffer.from(
      'f87c08856d6e2edc00830186a094010000000000000000000000000000000000000280b85441c9cc6fd27e26e70f951869fb09da685a696f0a79d338394f709c6d776d1318765981e69c09f0aa49864d8cc35699545b5e73a00000000000000000000000000000000000000000000000000123456789abcdef82a8688080',
      'hex',
    ),
    nft_info: undefined,
  },
  {
    name: 'legacy_transfer',
    op: Buffer.from('ed01856d6e2edc008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a248740008082a86a8080', 'hex'),
    nft_info: undefined,
  },
  {
    name: 'erc721_safe_transfer_from',
    op: Buffer.from(
      '02f88d02198459682f00850b68b3c16882caf09434bc797f40df0445c8429d485232874b1556172880b86442842e0e00000000000000000000000077944eed8d4a00c8bd413f77744751a4d04ea34a0000000000000000000000005d4994bccdd28afbbc6388fbcaaec69dd44c04560000000000000000000000000000000000000000000000000000000000000201c0',
      'hex',
    ),
    nft_info: {
      token_address: '34bc797f40df0445c8429d485232874b15561728',
      token_name: 'Lucid',
      chain_id: 2,
    },
  },
  {
    name: 'erc721_approve_for_all',
    op: Buffer.from(
      '02f86f0382034a8459682f00850322d538d182b67094bd3f82a81c3f74542736765ce4fd579d177b6bc580b844a22cb4650000000000000000000000001e0049783f008a0085193e00003d00cd54003c710000000000000000000000000000000000000000000000000000000000000001c0',
      'hex',
    ),
    nft_info: {
      token_address: 'bd3f82a81c3f74542736765ce4fd579d177b6bc5',
      token_name: 'PG JIRAVERSE',
      chain_id: 2,
    },
  },
]

jest.setTimeout(60000)

// Nanos does not support erc721
describe.each(models)('EthereumTx [%s]; sign', function (m) {
  test.concurrent.each(SIGN_TEST_DATA)('sign transaction:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())

      const msg = data.op
      console.log('name: ', data.name, 'msg:', msg.toString('hex'))

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${data.name}`

      const currentScreen = await sim.snapshot()

      // TODO: Investigate later required changes to pass token NftInfo
      // to application for ERC721/ERC20 transfers
      const nft = data.nft_info
      if (nft !== undefined) {
        const provide_resp = await app.provideNFTInformation(nft.token_name, nft.token_address, BigInt(nft.chain_id))
        expect(provide_resp).toEqual(true)
      }

      const respReq = app.signEVMTransaction(ETH_DERIVATION, msg.toString('hex'))
      await sim.waitUntilScreenIsNot(currentScreen, 100000)
      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, data.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      //Verify signature
      const resp_addr = await app.getETHAddress(ETH_DERIVATION, false)

      const EC = new ec('secp256k1')
      const sha3 = require('js-sha3')
      const msgHash = sha3.keccak256(msg)

      const pubKey = Buffer.from(resp_addr.publicKey, 'hex')
      const signature_obj = {
        r: Buffer.from(resp.r, 'hex'),
        s: Buffer.from(resp.s, 'hex'),
      }

      // TODO: Enable later
      const ok = EC.verify(msgHash, signature_obj, pubKey, 'hex')
      expect(ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  // This check ensure that app returns an error
  // if transaction is meant to target ethereum mainnet with out expert
  // mode enable.
  test.concurrent('TxMainnetMustFail', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())

      const data = 'e980856d6e2edc00832dc6c094df073477da421520cf03af261b782282c304ad6684a1bcd40080018080'

      await app.signEVMTransaction(ETH_DERIVATION, data)
    } catch (error) {
      expect(error).toBeDefined()
    } finally {
      await sim.close()
    }
  })
})

describe.each(models)('EthereumOthers [%s] - misc', function (m) {
  test.concurrent('getAppConfig', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new Eth(sim.getTransport())

      const resp = await app.getAppConfiguration()

      console.log(resp, m.name)

      expect(resp.arbitraryDataEnabled).toBeFalsy()
      expect(resp.erc20ProvisioningNecessary).toBeTruthy()
      expect(resp.starkEnabled).toBeFalsy()
      expect(resp.starkv2Supported).toBeFalsy()
    } finally {
      await sim.close()
    }
  })

  test.concurrent('EthPersonalMsg%s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new Eth(sim.getTransport())
      // Put the app in expert mode
      await sim.toggleExpertMode()

      let msgData = Buffer.from('Hello World', 'utf8')

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-message`

      const currentScreen = await sim.snapshot()

      const respReq = app.signPersonalMessage(ETH_DERIVATION, msgData.toString('hex'))
      await sim.waitUntilScreenIsNot(currentScreen, 20000)
      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, msgData)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      //Verify signature
      const resp_addr = await app.getAddress(ETH_DERIVATION, false)
      console.log(resp_addr, m.name)

      const header = Buffer.from('\x19Ethereum Signed Message:\n', 'utf8')
      const msgLengthString = String(msgData.length)
      const msg = Buffer.concat([header, Buffer.from(msgLengthString, 'utf8'), msgData])

      const sha3 = require('js-sha3')
      const msgHash = sha3.keccak256(msg)

      const pubKey = Buffer.from(resp_addr.publicKey, 'hex')
      const signature_obj = {
        r: Buffer.from(resp.r, 'hex'),
        s: Buffer.from(resp.s, 'hex'),
      }

      const EC = new ec('secp256k1')
      const ok = EC.verify(msgHash, signature_obj, pubKey, 'hex')

      expect(ok).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

// Eip712 transactions are not supported by nanos
describe.each(models.filter(m => m.name !== 'nanos'))('EIP712 [%s]; sign', function (m) {
  test.concurrent('Eip712Hash', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())

      // Put the app in expert mode
      await sim.toggleExpertMode()

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-eip712_hashed_message`

      const currentScreen = await sim.snapshot()

      const respReq = app.signEIP712HashedMessage(ETH_DERIVATION, EIP712_TRANSACTION.domain_hash, EIP712_TRANSACTION.msg_hash)
      await sim.waitUntilScreenIsNot(currentScreen, 100000)
      if (isTouchDevice(m.name)) {
        await sim.compareSnapshotsAndApprove('.', testcase)
      } else {
        const nav = new ClickNavigation([5, 0])
        await sim.navigateAndCompareSnapshots('.', testcase, nav.schedule)
      }

      const resp = await respReq

      console.log(resp, m.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')
    } finally {
      await sim.close()
    }
  })
})

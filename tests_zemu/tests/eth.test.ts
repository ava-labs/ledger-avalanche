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
import { ETH_DERIVATION, defaultOptions as commonOpts, defaultOptionsBlindSign, models } from './common'
import Eth from '@ledgerhq/hw-app-eth'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import { ec } from 'elliptic'

const defaultOptions = (model: any) => {
  let opts = commonOpts(model, false)
  return opts
}

const blindSignOptions = (model: any) => {
  return {
    ...defaultOptionsBlindSign,
    model: model.name,
  }
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
  // Set when the transaction targets a non-AVAX EVM chain (chain_id not in
  // {43114, 43113, 43112}). On the device the value field will render as
  // "???" and signing requires blind-sign mode to be enabled.
  foreign_chain?: boolean
  // On Nano X / SP, `compareSnapshotsAndApprove` searches events for the
  // case-insensitive keyword `/APPROVE/i`. ERC-20 `approve` flows render the
  // literal word "approve" as the function-name screen, which collides with
  // that keyword and trips a premature press-and-hold. Set this to the
  // number of right-clicks needed to reach the final APPROVE button so the
  // test drives navigation by click count instead. Touch devices (Stax /
  // Flex / Apex) are unaffected — their keyword is "Hold to sign".
  nano_clicks?: number
}

// copied from python tests
const EIP712_TRANSACTION = {
  domain_hash: 'c24f499b8c957196651b13edd64aaccc3980009674b2aea0966c8a56ba81278e',
  msg_hash: '9d96be8a7cca396e711a3ba356bd9878df02a726d753ddb6cda3c507d888bc77',
}

const SIGN_TEST_DATA: TestData[] = [
  {
    // EIP-1559 transfer on chain_id 5 (foreign)
    name: 'transfer',
    op: Buffer.from(
      '02f5058402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c0',
      'hex',
    ),
    nft_info: undefined,
    foreign_chain: true,
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
    // EIP-1559 ERC-721 safeTransferFrom on chain_id 2 (foreign)
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
    foreign_chain: true,
  },
  {
    // EIP-1559 ERC-721 setApprovalForAll on chain_id 3 (foreign)
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
    foreign_chain: true,
  },
  {
    name: 'erc20_transfer_usdt',
    op: Buffer.from(
      'f86d820968850565614c4282b0a4949702230a8ea53601f5cd2dc00fdbc13d4df4a8c780b844a9059cbb000000000000000000000000b1aaa26254b251e45af9988bc9beed3f3ef6b36f0000000000000000000000000000000000000000000000000000000008ae253182a86a8080',
      'hex',
    ),
    nft_info: undefined,
  },
  {
    name: 'erc20_transfer_1inch_e',
    op: Buffer.from(
      'f86e820f588502fed078ac83014d7694d501281565bf7789224523144fe5d98e8b28f26780b844a9059cbb0000000000000000000000002a1f67dd9e32d4b7d306d1343bf359809ca334e500000000000000000000000000000000000000000000000627521c2ad387400082a86a8080',
      'hex',
    ),
    nft_info: undefined,
  },
  {
    // approve(spender, MAX_UINT256) against the USDC.e contract on C-Chain
    // (43114). Exercises the "Unlimited <SYMBOL>" render branch added in
    // erc20.rs::format_approve_amount — the device should display the amount
    // as "Unlimited USDC.e" rather than the 78-digit decimal expansion of
    // 2^256 - 1. Spender is an arbitrary 20-byte address.
    name: 'erc20_approve_max_usdc_e',
    op: Buffer.from(
      'f86c80850565614c4283014d7694a7d7079b0fead91f3e65f86e8915cb59c1a4c66480b844095ea7b30000000000000000000000005de0f44ca827bf03f87a87985bf08669050c73ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82a86a8080',
      'hex',
    ),
    nft_info: undefined,
    // 7 mirrors the existing erc20_transfer snapshot depth (9 frames: initial
    // + 7 right + 1 both). Bump if the approve flow renders an extra screen.
    nano_clicks: 7,
  },
  {
    // Real-world reproduction of the JUICE-swap-displays-as-AVAX bug:
    // EIP-2930 transfer of 2000 JUICE on Orange L1 (chain_id 1510), the
    // exact tx that prompted this fix. Before the fix the device would
    // render "Transfer: AVAX 2000" — under the foreign-chain rule it now
    // renders "Transfer: ??? 2000" and gates signing on blind-sign mode.
    // Source: https://explorer.avax.network/orange/tx/0x70c7d73020235b715d30f1f6a479915c4a65a2c14e90f67d572849e03c680540
    name: 'orange_juice_swap_eip2930',
    op: Buffer.from(
      '01f906d58205e68085091494c600830687b894fff1e335bccc178de27ad211c1ee4f7ab7ee6938896c6b935b8bbd400000b906a4f3a027a6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c6b935b8bbd4000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000e6370eccca56ca0ff8e9b3a3b31d0a81f3e9bff0000000000000000000000009da1e81b4e0aafdf98e35e15ff8542331702c8cd00000000000000000000000000000000000000000000000000000000000000010000000000000000000000009da1e81b4e0aafdf98e35e15ff8542331702c8cd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007a12000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000002dc6c000000000000000000000000000000000000000000000000000000000002625a0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000007fe5886dc5397f3d2b0406b1b1de071b5463870000000000000000000000000000000000000000000000000000000000000000100000000000000000000000007fe5886dc5397f3d2b0406b1b1de071b5463870000000000000000000000000b7b1416b9c91efd69c9245958be08b5cad4549540427d4b22a2a78bcddd456742caf91b56badbff985ee19aef14573e7343fd6520000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000027fa6000000000000000000000000000000000000000000000000000000000002059400000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b7b1416b9c91efd69c9245958be08b5cad4549540427d4b22a2a78bcddd456742caf91b56badbff985ee19aef14573e7343fd65200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c341080bd1fb000000000000000000000000000000000000000000000000000000133db155d1d583b000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000002000000000000000000000000d5d053d5b769383e860d1520da7a908e00919f36000000000000000000000000b31f66aa3c1e785363f0875a1b74e27b85fd66c70000000000000000000000000000000000000000000000000000000000000001000000000000000000000000db66686ac8bea67400cf9e5dd6c8849575b90148c0',
      'hex',
    ),
    nft_info: undefined,
    foreign_chain: true,
  },

]

const ETH_MSG_RAW: number[] = [
  ...Buffer.from('Hello, ', 'utf8'),
  0x80,
  ...Buffer.from('World! ', 'utf8'),
  0x81,
  ...Buffer.from('This is a ', 'utf8'),
  0x82,
  ...Buffer.from('complex ', 'utf8'),
  0x83,
  ...Buffer.from('test ', 'utf8'),
  0x84,
  ...Buffer.from('vector with ', 'utf8'),
  0x85,
  0x86,
  0x87,
  ...Buffer.from(' multiple non-ASCII ', 'utf8'),
  0x88,
  0x89,
  ...Buffer.from(' characters ', 'utf8'),
  0x8a,
  ...Buffer.from('scattered ', 'utf8'),
  0x8b,
  ...Buffer.from('throughout. ', 'utf8'),
  0x8c,
  0x8d,
  0x8e,
  0x8f,
  ...Buffer.from('It should ', 'utf8'),
  0x90,
  ...Buffer.from('properly ', 'utf8'),
  0x91,
  ...Buffer.from('chunk ', 'utf8'),
  0x92,
  ...Buffer.from('and format.', 'utf8'),
]

jest.setTimeout(60000)

// Nanos does not support erc721
describe.each(models)('EthereumTx [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign transaction:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      // Foreign-chain txs require blind-sign mode: the device cannot resolve
      // the native ticker symbol so it renders "???" and gates signing on the
      // blind-sign toggle being on. Mirror the large_tx_sign blind-sign setup.
      await sim.start(data.foreign_chain ? blindSignOptions(m) : defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())

      if (data.foreign_chain) {
        await sim.toggleBlindSigning()
      }

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
      if (data.nano_clicks !== undefined && !isTouchDevice(m.name)) {
        const nav = new ClickNavigation([data.nano_clicks, 0])
        await sim.navigateAndCompareSnapshots('.', testcase, nav.schedule)
      } else {
        await sim.compareSnapshotsAndApprove('.', testcase, true, 0, 1500, !!data.foreign_chain)
      }

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

  // Foreign-chain transactions must be rejected when blind-sign mode is off,
  // mirroring how the upstream Ledger Ethereum app refuses to sign on chains
  // it cannot resolve a ticker for. Same EIP-1559 transfer payload as the
  // `transfer` SIGN_TEST_DATA entry (chain_id 5).
  //
  // Regression guard: the app must SHOW the blind-sign warning screen, not just
  // reject. A Rust/C enum mismatch (ParserError::BlindSignNotEnabled = 42 vs
  // parser_blind_sign_not_enabled = 41) once made the device skip
  // view_blindsign_error_show() and return a bare 0x6984 with no screen. We
  // assert the warning text appears: it never does on the buggy build (the call
  // rejects immediately with no UI), so waitForText times out and the test fails.
  test.concurrent('ForeignChainMustFail', async function () {
    const sim = new Zemu(m.path)
    // signEVMTransaction is deferred (IO_ASYNCH_REPLY) once the warning shows and
    // only settles when the screen is dismissed — here, when the container closes.
    // Definite assignment: it is always set in the try below before any use.
    let signReq!: Promise<unknown>
    try {
      await sim.start(defaultOptions(m)) // blind signing OFF
      const app = new AvalancheApp(sim.getTransport())

      const data =
        '02f5058402a8af41843b9aca00850d8c7b50e68303d090944a2962ac08962819a8a17661970e3c0db765565e8817addd0864728ae780c0'

      // Explicit null resolution: skip hw-app-eth's client-side token lookup so
      // the raw tx reaches the device and its own blind-sign gate decides.
      signReq = app.signEVMTransaction(ETH_DERIVATION, data, null)
      signReq.catch(() => {}) // pre-attach: avoid unhandled rejection on teardown

      // Touch devices render "This transaction cannot be clear-signed"; Nano
      // devices render "Blind signing must be enabled in Settings".
      const warning = isTouchDevice(m.name) ? /clear-signed/i : /Blind signing must be/i
      await sim.waitForText(warning, 20000)
    } finally {
      await sim.close()
    }

    // It must have refused to sign (rejected), never produced a signature.
    await expect(signReq).rejects.toBeDefined()
  })
})

describe.each(models)('EthereumOthers [%s] - misc', function (m) {
  test.concurrent('getAppConfig', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new Eth(sim.getTransport() as any)

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
})

describe.each(models)('Ethereum Personal Message [%s] - misc', function (m) {
  test.concurrent('eth_msg sign%s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new Eth(sim.getTransport() as any)
      // Put the app in expert mode
      await sim.toggleExpertMode()

      // Initialize array to hold the message content
      let msgData = Buffer.from(ETH_MSG_RAW)

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
    } finally {
      await sim.close()
    }
  })

  test.concurrent('eth_msg sign complex nav approve%s', async function () {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new Eth(sim.getTransport() as any)
      // Put the app in expert mode
      await sim.toggleExpertMode()

      // Initialize array to hold the message content
      let msgData = Buffer.from(ETH_MSG_RAW)

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-message-complex_nav`

      const currentScreen = await sim.snapshot()

      const respReq = app.signPersonalMessage(ETH_DERIVATION, msgData.toString('hex'))

      if (m.name === 'nanos') {
        await sim.navigateAndCompareSnapshots('.', testcase, [6, -4, 3, 0, 0])
      } else if (m.name === 'nanox' || m.name === 'nanosp') {
        await sim.navigateAndCompareSnapshots('.', testcase, [9, -4, 3, 0, 0])
      } else {
        // skip menu is not available for larger devices
        // like stax and flex
        await sim.waitUntilScreenIsNot(currentScreen, 20000)
        await sim.compareSnapshotsAndApprove('.', testcase)
      }

      const resp = await respReq

      console.log(resp, m.name, msgData)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')
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

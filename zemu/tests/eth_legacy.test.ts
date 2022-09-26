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
import { ETH_DERIVATION, defaultOptions, models, enableBlindSigning } from './common'
import Eth from '@ledgerhq/hw-app-eth'
import { Transaction, FeeMarketEIP1559Transaction } from "@ethereumjs/tx"; 
import Common from '@ethereumjs/common'
import { bnToRlp, rlp } from "ethereumjs-util";
import { ec } from 'elliptic'
const BN = require('bn.js');


const SIGN_TEST_DATA = [
  {
    name: 'basic_transfer',
    op: {
        value: 'abcdef00',
        to: 'df073477da421520cf03af261b782282c304ad66',
    } 
  },
  {
    name: 'legacy_contract_deploy',
    op: {
        value: 'abcdef00',
        data: '1a8451e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    } 
  },
  {
    name: 'legacy_contract_call',
    op: {
        to: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
        value: 'abcdef00',
        data: 'ee919d500000000000000000000000000000000000000000000000000000000000000001',
    } 
  },
  {
    name: 'erc20_transfer',
    op: {
        // this is not probably the contract address but lets use it
        to: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
        value: '0',
        data: 'a9059cbb0000000000000000000000005f658a6d1928c39b286b48192fea8d46d87ad07700000000000000000000000000000000000000000000000000000000000f4240',
    } 
  },
  {
    name: 'pangolin_contract_call',
    op: {
        // Pangolin AVAX/DAI swap 2
        to: '62650ae5c5777d1660cc17fcd4f550000eacdfa0',
        value: '0',
        data: '8a657e670000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000c7b9b39ab3081ac34fc4324e3f648b55528871970000000000000000000000000000000000000000000000000000017938e114be0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000b31f66aa3c1e785363f0875a1b74e27b85fd66c7000000000000000000000000ba7deebbfc5fa1100fb055a87773e1e99cd3507a',
    } 
  },
  {
    name: 'erc721_approve',
    op: {
        // this is not probably the contract address but lets use it
        to: '62650ae5c5777d1660cc17fcd4f48f6a66b9a4c2',
        value: '0',
        data: '095ea7b30000000000000000000000005f658a6d1928c39b286b48192fea8d46d87ad07700000000000000000000000000000000000000000000000000000000000f4240',
    } 
  },
]

const rawUnsignedLegacyTransaction = (params: any, chainId=43112) => {

    const txParams = {
        nonce: '0x00',
        gasPrice: '0x6d6e2edc00',
        gasLimit: '0x2dc6c0',
        to: params.to !== undefined? '0x' + params.to: undefined,
        value: '0x' + params.value,
        data: params.data !== undefined? '0x' + params.data: undefined,
    }

    const common = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId });

    //// legacy
    const tx = Transaction.fromTxData(txParams, {common})

    return rlp.encode([
        bnToRlp(tx.nonce),
        bnToRlp(tx.gasPrice),
        bnToRlp(tx.gasLimit),
        tx.to !== undefined ? tx.to.buf : Buffer.from([]),
        bnToRlp(tx.value),
        tx.data,
        bnToRlp(new BN(chainId)),
        Buffer.from([]),
        Buffer.from([]),
    ]);

};

// an alternative verification method for legacy transactions, taken from obsidian
function check_legacy_signature(hexTx: string, signature: any, chainId=43112) {
  const ethTx = Buffer.from(hexTx, 'hex');

  const chain = Common.forCustomChain(1, { name: 'avalanche', networkId: 1, chainId });

  const txnBufsDecoded: any = rlp.decode(ethTx).slice(0,6);
  const txnBufsMap = [signature.v, signature.r, signature.s].map(a=>Buffer.from(((a.length%2==1)?'0'+a:a),'hex'));

  const txnBufs = txnBufsDecoded.concat(txnBufsMap);

  const ethTxObj = Transaction.fromValuesArray(txnBufs, {common: chain});

  return ethTxObj.verifySignature()
}

describe.each(models)('EthereumLegacy [%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign legacy:  $name', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new Eth(sim.getTransport())

      const testcase = `${m.prefix.toLowerCase()}-eth-sign-${data.name}`

      const currentScreen = sim.snapshot()
      const msg = rawUnsignedLegacyTransaction(data.op);

      const respReq = app.signTransaction(ETH_DERIVATION, msg.toString('hex'), null)
      await sim.waitUntilScreenIsNot(currentScreen, 20000)
      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      console.log(resp, m.name, data.name)

      expect(resp).toHaveProperty('s')
      expect(resp).toHaveProperty('r')
      expect(resp).toHaveProperty('v')

      //Verify signature
     const resp_addr = await app.getAddress(ETH_DERIVATION, false)

      const EC = new ec("secp256k1");
      const sha3 = require('js-sha3');
      const msgHash = sha3.keccak256(msg);

      const pubKey = Buffer.from(resp_addr.publicKey, 'hex')
      const signature_obj = {
        r: Buffer.from(resp.r, 'hex'),
        s: Buffer.from(resp.s, 'hex'),
      }

      const signatureOK = EC.verify(msgHash, signature_obj, pubKey, 'hex')
      expect(signatureOK).toEqual(true)

      // alternative verification to be safe
      const test = await check_legacy_signature(msg.toString('hex'),resp)
      expect(test).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

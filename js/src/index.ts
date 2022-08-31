/** ******************************************************************************
 *  (c) 2019-2020 Zondax GmbH
 *  (c) 2016-2017 Ledger
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
import Transport from '@ledgerhq/hw-transport'
import { serializePath, serializePathSuffix, serializeHrp, serializeChainID, pathCoinType } from './helper'
import { ResponseAddress, ResponseAppInfo, ResponseBase, ResponseSign, ResponseVersion, ResponseWalletId, ResponseXPub } from './types'
import {
  CHUNK_SIZE,
  CLA,
  CLA_ETH,
  Curve,
  errorCodeToString,
  getVersion,
  INS,
  LedgerError,
  P1_VALUES,
  PAYLOAD_TYPE,
  processErrorResponse,
  FIRST_MESSAGE,
  LAST_MESSAGE,
  HASH_LEN,
} from './common'

export { LedgerError, Curve }
export * from './types'

function processGetAddrResponse(response: Buffer) {
  let partialResponse = response

  const errorCodeData = partialResponse.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  //get public key len (variable)
  const PKLEN = partialResponse[0]
  const publicKey = Buffer.from(partialResponse.slice(1, 1 + PKLEN))

  //"advance" buffer
  partialResponse = partialResponse.slice(1 + PKLEN)

  const hash = Buffer.from(partialResponse.slice(0, -2))

  return {
    publicKey,
    hash,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

function processGetXPubResponse(response: Buffer) {
  let partialResponse = response

  const errorCodeData = partialResponse.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  //get public key len (variable)
  const PKLEN = partialResponse[0]
  const publicKey = Buffer.from(partialResponse.slice(1, 1 + PKLEN))

  //"advance" buffer
  partialResponse = partialResponse.slice(1 + PKLEN)

  const chain_code = Buffer.from(partialResponse.slice(0, -2))

  return {
    publicKey,
    chain_code,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  }
}

export default class AvalancheApp {
  transport

  constructor(transport: Transport) {
    this.transport = transport
    if (!transport) {
      throw new Error('Transport has not been defined')
    }
  }

  private static prepareChunks(message: Buffer, serializedPathBuffer?: Buffer) {
    const chunks = []

    // First chunk (only path)
    if (serializedPathBuffer !== undefined) {
      // First chunk (only path)
      chunks.push(serializedPathBuffer!)
    }

    const messageBuffer = Buffer.from(message)

    const buffer = Buffer.concat([messageBuffer])
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE
      if (i > buffer.length) {
        end = buffer.length
      }
      chunks.push(buffer.slice(i, end))
    }

    return chunks
  }

  private async signGetChunks(message: Buffer, path?: string) {
    if (path === undefined) {
      return AvalancheApp.prepareChunks(message, Buffer.alloc(0))
    } else {
      return AvalancheApp.prepareChunks(message, serializePath(path))
    }
  }

  private concatMessageAndChangePath(message: Buffer, path?: Array<string>): Buffer {
      // data
    let msg = Buffer.concat([message]);
    // no change_path
    if (path === undefined) {
      let buffer = Buffer.alloc(1);
      buffer.writeUInt8(0);
      return Buffer.concat([buffer, msg]);
    } else {
      let buffer = Buffer.alloc(1);
      buffer.writeUInt8(path.length);
      path.forEach( (element) => {
        buffer = Buffer.concat([buffer, serializePathSuffix(element)]);

      });
      return Buffer.concat([buffer, msg]);
    }

  }

  private async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, param?: Curve, ins: number = INS.SIGN, evm = false): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD
    let p2 = 0
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT
      if (param === undefined) {
        throw Error('curve or number type not given')
      }
      p2 = param
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST
    }

    const cla = evm ? CLA_ETH : CLA;

    return this.transport
      .send(cla, ins, payloadType, p2, chunk, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          return {
            hash: null,
            signature: null,
            returnCode: returnCode,
            errorMessage: errorMessage,
          }
        }

        return {
          returnCode: returnCode,
          errorMessage: errorMessage,
        }
      }, processErrorResponse)
  }

  // The preamble consist of the root path which is set before sending
  // the remaining data to be show/signed
  async send_preamble(path: string, curve: Curve, evm = false): Promise<ResponseSign> {
    const serializedPath = serializePath(path);
    return this.transport
      .send(CLA, INS.PREAMBLE, 0, curve, Buffer.concat([serializedPath]), [LedgerError.NoErrors])
      .then((response: Buffer) => {
        const errorCodeData = response.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid
        ) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
        }
        return {
          returnCode: returnCode,
          errorMessage: errorMessage,
        }
      }, processErrorResponse)
  }

   async signHash(path_prefix: string, signing_paths: Array<string>, hash: Buffer, is_eth = false): Promise<ResponseSign> {

     if (hash.length !== HASH_LEN) {
      throw new Error('Invalid hash length');
     }

    const cla = is_eth ? CLA_ETH : CLA;

    // Set root path and curve
    let response = await this.send_preamble(path_prefix, Curve.Secp256K1, is_eth);
    if (response.returnCode !== LedgerError.NoErrors) {
      return response;
    }

    // send hash
    const first_response = await this.transport
      .send(cla, INS.SIGN_HASH, FIRST_MESSAGE, 0x00, Buffer.concat([hash]), [LedgerError.NoErrors])
      .then((response: Buffer) => {
        const errorCodeData = response.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid
        ) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
        }
        return {
          returnCode: returnCode,
          errorMessage: errorMessage,
        }
      }, processErrorResponse)

    if (first_response.returnCode !== LedgerError.NoErrors) {
      return first_response;
    }

    return this._signAndCollect(signing_paths)
  }

  private async _signAndCollect(signing_paths: Array<string>): Promise<ResponseSign> {
    // base response object to output on each iteration
    let result = {
      returnCode: LedgerError.NoErrors,
      errorMessage:"",
      hash: null,
      signatures: null as null | Buffer | Map<string, Buffer>,
    };

    // where each pair path_suffix, signature are stored
    let signatures = new Map();

    for (let idx = 0; idx < signing_paths.length; idx++) {
      const suffix = signing_paths[idx];
      const path_buf = serializePathSuffix(suffix);

      const p1 = idx >= signing_paths.length - 1 ? LAST_MESSAGE : 0x80;

      // send path to sign hash that should be in device's ram memory
      await this.transport.send(CLA, INS.SIGN_HASH, p1, 0x00, path_buf, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          result.errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          signatures.set(suffix, response.slice(0, -2));
        }

        result.returnCode = returnCode;
        result.errorMessage = errorMessage;

        return
      }, processErrorResponse);

      if (result.returnCode !== LedgerError.NoErrors) {
        break;
      }
    };
    result.signatures = signatures;
    return result;
  }

  async sign(path_prefix: string, signing_paths: Array<string>, message: Buffer, change_paths?: Array<string>): Promise<ResponseSign> {
    const coinType = pathCoinType(path_prefix);

    let is_eth: boolean;
    switch (coinType) {
      case "9000\'":
        is_eth = false
        break;
      case "60\'":
        is_eth = true
        break;
      default:
        throw "Path's cointype should be either 60\' or 9000\'"
    }
    let curve = Curve.Secp256K1;

    // Set the root path and the curve
    let res_preamble = await this.send_preamble(path_prefix, curve, is_eth)
    if (res_preamble.returnCode !== LedgerError.NoErrors) {
      return res_preamble;
    }

    // Do not show outputs that go to the signers
    let paths = signing_paths;
    if (change_paths !== undefined ) {
      paths = paths.concat(change_paths);
    }

    // Prepend change_paths to the message as the device do set which outputs should be
    // shown at parsing
    const msg = this.concatMessageAndChangePath(message, paths);

    // Send transaction for review
    let response = await this.signGetChunks(msg).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], curve, INS.SIGN, is_eth).then(async response => {
        // initialize response
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signatures: null as null | Buffer | Map<string, Buffer>,
        }

        // send chunks
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], Curve.Secp256K1, INS.SIGN, is_eth)
          if (result.returnCode !== LedgerError.NoErrors) {
            break
          }
        }
        return result
      }, processErrorResponse)
    }, processErrorResponse)

    if (response.returnCode !== LedgerError.NoErrors) {
      return response;
    }

    // Transaction was approved so start iterating over signing_paths to sign
    // and collect each signature
    return this._signAndCollect(signing_paths);
  }

  async getVersion(): Promise<ResponseVersion> {
    return getVersion(this.transport).catch(err => processErrorResponse(err))
  }

  async getAppInfo(): Promise<ResponseAppInfo> {
    return this.transport.send(0xb0, 0x01, 0, 0).then(response => {
      const errorCodeData = response.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      const result: { errorMessage?: string; returnCode?: LedgerError } = {}

      let appName = 'err'
      let appVersion = 'err'
      let flagLen = 0
      let flagsValue = 0

      if (response[0] !== 1) {
        // Ledger responds with format ID 1. There is no spec for any format != 1
        result.errorMessage = 'response format ID not recognized'
        result.returnCode = LedgerError.DeviceIsBusy
      } else {
        const appNameLen = response[1]
        appName = response.slice(2, 2 + appNameLen).toString('ascii')
        let idx = 2 + appNameLen
        const appVersionLen = response[idx]
        idx += 1
        appVersion = response.slice(idx, idx + appVersionLen).toString('ascii')
        idx += appVersionLen
        const appFlagsLen = response[idx]
        idx += 1
        flagLen = appFlagsLen
        flagsValue = response[idx]
      }

      return {
        returnCode,
        errorMessage: errorCodeToString(returnCode),
        //
        appName,
        appVersion,
        flagLen,
        flagsValue,
        flagRecovery: (flagsValue & 1) !== 0,
        // eslint-disable-next-line no-bitwise
        flagSignedMcuCode: (flagsValue & 2) !== 0,
        // eslint-disable-next-line no-bitwise
        flagOnboarded: (flagsValue & 4) !== 0,
        // eslint-disable-next-line no-bitwise
        flagPINValidated: (flagsValue & 128) !== 0,
      }
    }, processErrorResponse)
  }

  private async _pubkey(path: string, curve: Curve, show: boolean, evm = false, hrp?: string, chainid?: string): Promise<ResponseAddress> {
    const p1 = show ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE;
    const serializedPath = serializePath(path)
    const serializedHrp = evm ? Buffer.alloc(0) : serializeHrp(hrp)
    const serializedChainID = evm ? Buffer.alloc(0) : serializeChainID(chainid);

    const cla = evm ? CLA_ETH : CLA;

    return this.transport
      .send(cla, INS.GET_ADDR, p1, curve, Buffer.concat([serializedHrp, serializedChainID, serializedPath]), [LedgerError.NoErrors])
      .then(processGetAddrResponse, processErrorResponse)
  }

  async getAddressAndPubKey(path: string, show: boolean, hrp?: string, chainid?: string) {
    const coinType = pathCoinType(path);

    let is_eth: boolean;
    switch (coinType) {
      case "9000\'":
        is_eth = false
        break;
      case "60\'":
        is_eth = true
        break;
      default:
        throw "Path's cointype should be either 60\' or 9000\'"
    }

    return this._pubkey(path, Curve.Secp256K1, show, is_eth, hrp, chainid)
  }

  private async _xpub(path: string, curve: Curve, show: boolean, evm = false, hrp?: string, chainid?: string): Promise<ResponseXPub> {
    const p1 = show ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE;
    const serializedPath = serializePath(path)
    const serializedHrp = evm ? Buffer.alloc(0) : serializeHrp(hrp)
    const serializedChainID = evm ? Buffer.alloc(0) : serializeChainID(chainid);

    const cla = evm ? CLA_ETH : CLA;

    return this.transport
      .send(cla, INS.GET_EXTENDED_PUBLIC_KEY, p1, curve, Buffer.concat([serializedHrp, serializedChainID, serializedPath]), [LedgerError.NoErrors])
      .then(processGetXPubResponse, processErrorResponse)
  }

  async getExtendedPubKey(path: string, show: boolean, hrp?: string, chainid?: string) {
    const coinType = pathCoinType(path);

    let is_eth: boolean;
    switch (coinType) {
      case "9000\'":
        is_eth = false
        break;
      case "60\'":
        is_eth = true
        break;
      default:
        throw "Path's cointype should be either 60\' or 9000\'"
    }

    return this._xpub(path, Curve.Secp256K1, show, is_eth, hrp, chainid)
  }

  private async _walletId(show: boolean, curve: Curve): Promise<ResponseWalletId> {
    const p1 = show ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE;

    return this.transport
      .send(CLA, INS.WALLET_ID, p1, curve)
      .then(response => {
        const errorCodeData = response.slice(-2)
        const returnCode = (errorCodeData[0] * 256 + errorCodeData[1]) as LedgerError

        return {
          returnCode,
          errorMessage: errorCodeToString(returnCode),
          id: response.slice(0, 6),
        }
      }, processErrorResponse)
  }

  async getWalletId(curve: Curve) {
    return this._walletId(false, curve)
  }

  async showWalletId(curve: Curve) {
    return this._walletId(true, curve)
  }
}

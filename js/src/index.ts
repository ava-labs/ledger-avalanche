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
import { serializePath, serializeHrp, serializeChainID, pathCoinType } from './helper'
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

  private async signGetChunks(path: string, message: Buffer) {
    return AvalancheApp.prepareChunks(message, serializePath(path))
  }

  private async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, curve?: Curve, ins: number = INS.SIGN, evm = false): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD
    let p2 = 0
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT
      if (curve === undefined) {
        throw Error('curve type not given')
      }
      p2 = curve
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
            hash: response.slice(0, 32),
            signature: response.slice(32, -2),
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

  async sign(path: string, message: Buffer): Promise<ResponseSign> {
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

    return this.signGetChunks(path, message).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], Curve.Secp256K1, INS.SIGN, is_eth).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signature: null as null | Buffer,
        }
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

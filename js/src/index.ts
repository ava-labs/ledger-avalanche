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
import {
  CHAIN_ID_SIZE,
  CHUNK_SIZE,
  CLA,
  CLA_ETH,
  COLLECTION_NAME_MAX_LEN,
  ADDRESS_LENGTH,
  ALGORITHM_ID_1,
  ALGORITHM_ID_SIZE,
  TYPE_SIZE,
  VERSION_SIZE,
  SIGNATURE_LENGTH_SIZE,
  CONTRACT_ADDRESS_LEN,
  errorCodeToString,
  FIRST_MESSAGE,
  getVersion,
  HASH_LEN,
  INS,
  LAST_MESSAGE,
  LedgerError,
  NEXT_MESSAGE,
  P1_VALUES,
  PAYLOAD_TYPE,
  processErrorResponse,
  TYPE_1,
  VERSION_1,
} from './common'
import { pathCoinType, serializeChainID, serializeHrp, serializePath, serializePathSuffix } from './helper'
import { ResponseAddress, ResponseAppInfo, ResponseBase, ResponseSign, ResponseVersion, ResponseWalletId, ResponseXPub } from './types'

import Eth from '@ledgerhq/hw-app-eth'

import { LedgerEthTransactionResolution, LoadConfig, ResolutionConfig } from '@ledgerhq/hw-app-eth/lib/services/types'
import { EIP712Message } from '@ledgerhq/types-live'

export * from './types'
export { LedgerError }

function processGetAddrResponse(response: Buffer) {
  let partialResponse = response

  const errorCodeData = partialResponse.slice(-2)
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

  //get public key len (variable)
  const PKLEN = partialResponse[0]
  const publicKey = Buffer.from(partialResponse.slice(1, 1 + PKLEN))

  //"advance" buffer
  partialResponse = partialResponse.slice(1 + PKLEN)

  const hash = Buffer.from(partialResponse.slice(0, 20))

  //"advance" buffer
  partialResponse = partialResponse.slice(20)

  const address = Buffer.from(partialResponse.subarray(0, -2)).toString()

  return {
    publicKey,
    hash,
    address,
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
  private eth

  constructor(transport: Transport, ethScrambleKey = 'w0w', ethLoadConfig: LoadConfig = {}) {
    this.transport = transport
    if (!transport) {
      throw new Error('Transport has not been defined')
    }

    this.eth = new Eth(transport, ethScrambleKey, ethLoadConfig)
  }

  private static prepareChunks(message: Buffer, serializedPathBuffer?: Buffer) {
    const chunks = []

    // First chunk (only path)
    if (serializedPathBuffer !== undefined) {
      // First chunk (only path)
      chunks.push(serializedPathBuffer)
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
    const msg = Buffer.concat([message])
    // no change_path
    if (path === undefined) {
      const buffer = Buffer.alloc(1)
      buffer.writeUInt8(0)
      return Buffer.concat([buffer, msg])
    } else {
      let buffer = Buffer.alloc(1)
      buffer.writeUInt8(path.length)
      path.forEach(element => {
        buffer = Buffer.concat([buffer, serializePathSuffix(element)])
      })
      return Buffer.concat([buffer, msg])
    }
  }

  private async signSendChunk(
    chunkIdx: number,
    chunkNum: number,
    chunk: Buffer,
    param?: number,
    ins: number = INS.SIGN,
  ): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD
    let p2 = 0
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT
      if (param === undefined) {
        throw Error('number type not given')
      }
      p2 = param
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST
    }

    return this.transport
      .send(CLA, ins, payloadType, p2, chunk, [
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

  async signHash(path_prefix: string, signing_paths: Array<string>, hash: Buffer): Promise<ResponseSign> {
    if (hash.length !== HASH_LEN) {
      throw new Error('Invalid hash length')
    }

    //send hash and path
    const first_response = await this.transport
      .send(CLA, INS.SIGN_HASH, FIRST_MESSAGE, 0x00, Buffer.concat([serializePath(path_prefix), hash]), [LedgerError.NoErrors])
      .then((response: Buffer) => {
        const errorCodeData = response.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
        let errorMessage = errorCodeToString(returnCode)

        if (returnCode === LedgerError.BadKeyHandle || returnCode === LedgerError.DataIsInvalid) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
        }
        return {
          returnCode: returnCode,
          errorMessage: errorMessage,
        }
      }, processErrorResponse)

    if (first_response.returnCode !== LedgerError.NoErrors) {
      return first_response
    }

    return this._signAndCollect(signing_paths)
  }

  private async _signAndCollect(signing_paths: Array<string>): Promise<ResponseSign> {
    // base response object to output on each iteration
    const result = {
      returnCode: LedgerError.NoErrors,
      errorMessage: '',
      hash: null,
      signatures: null as null | Map<string, Buffer>,
    }

    // where each pair path_suffix, signature are stored
    const signatures = new Map()

    for (let idx = 0; idx < signing_paths.length; idx++) {
      const suffix = signing_paths[idx]
      const path_buf = serializePathSuffix(suffix)

      const p1 = idx >= signing_paths.length - 1 ? LAST_MESSAGE : NEXT_MESSAGE

      // send path to sign hash that should be in device's ram memory
      await this.transport
        .send(CLA, INS.SIGN_HASH, p1, 0x00, path_buf, [
          LedgerError.NoErrors,
          LedgerError.DataIsInvalid,
          LedgerError.BadKeyHandle,
          LedgerError.SignVerifyError,
        ])
        .then((response: Buffer) => {
          const errorCodeData = response.slice(-2)
          const returnCode = errorCodeData[0] * 256 + errorCodeData[1]
          const errorMessage = errorCodeToString(returnCode)

          if (
            returnCode === LedgerError.BadKeyHandle ||
            returnCode === LedgerError.DataIsInvalid ||
            returnCode === LedgerError.SignVerifyError
          ) {
            result.errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString('ascii')}`
          }

          if (returnCode === LedgerError.NoErrors && response.length > 2) {
            signatures.set(suffix, response.slice(0, -2))
          }

          result.returnCode = returnCode
          result.errorMessage = errorMessage

          return
        }, processErrorResponse)

      if (result.returnCode !== LedgerError.NoErrors) {
        break
      }
    }
    result.signatures = signatures
    return result
  }

  async sign(path_prefix: string, signing_paths: Array<string>, message: Buffer, change_paths?: Array<string>): Promise<ResponseSign> {
    // Do not show outputs that go to the signers
    let paths = signing_paths
    if (change_paths !== undefined) {
      // remove duplication just is case
      paths = [...new Set([...paths, ...change_paths])]
    }

    // Prepend change_paths to the message as the device do set which outputs should be
    // shown at parsing
    const msg = this.concatMessageAndChangePath(message, paths)

    // Send transaction for review
    const response = await this.signGetChunks(msg, path_prefix).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], FIRST_MESSAGE, INS.SIGN).then(async response => {
        // initialize response
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signatures: null as null | Map<string, Buffer>,
        }

        // send chunks
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], NEXT_MESSAGE, INS.SIGN)
          if (result.returnCode !== LedgerError.NoErrors) {
            break
          }
        }
        return result
      }, processErrorResponse)
    }, processErrorResponse)

    if (response.returnCode !== LedgerError.NoErrors) {
      return response
    }

    // Transaction was approved so start iterating over signing_paths to sign
    // and collect each signature
    return this._signAndCollect(signing_paths)
  }

  // Sign an arbitrary message.
  // This function takes in an avax path prefix like: m/44'/9000'/0'/0'
  // signing_paths: ["0/1", "5/8"]
  // message: The message to be signed
  async signMsg(path_prefix: string, signing_paths: Array<string>, message: string): Promise<ResponseSign> {
    const coinType = pathCoinType(path_prefix)

    if (coinType !== "9000'") {
      throw new Error('Only avax path is supported')
    }

    const header = Buffer.from('\x1AAvalanche Signed Message:\n', 'utf8')

    const content = Buffer.from(message, 'utf8')

    const msgSize = Buffer.alloc(4)
    msgSize.writeUInt32BE(content.length, 0)

    const avax_msg = Buffer.from(`${header}${msgSize}${content}`, 'utf8')

    // Send msg for review
    const response = await this.signGetChunks(avax_msg, path_prefix).then(chunks => {
      return this.signSendChunk(1, chunks.length, chunks[0], FIRST_MESSAGE, INS.SIGN_MSG).then(async response => {
        // initialize response
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signatures: null as null | Map<string, Buffer>,
        }

        // send chunks
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], NEXT_MESSAGE, INS.SIGN_MSG)
          if (result.returnCode !== LedgerError.NoErrors) {
            break
          }
        }
        return result
      }, processErrorResponse)
    }, processErrorResponse)

    if (response.returnCode !== LedgerError.NoErrors) {
      return response
    }

    // Message was approved so start iterating over signing_paths to sign
    // and collect each signature
    return this._signAndCollect(signing_paths)
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

  private async _pubkey(path: string, show: boolean, hrp?: string, chainid?: string): Promise<ResponseAddress> {
    const p1 = show ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE
    const serializedPath = serializePath(path)
    const serializedHrp = serializeHrp(hrp)
    const serializedChainID = serializeChainID(chainid)

    return this.transport
      .send(CLA, INS.GET_ADDR, p1, 0, Buffer.concat([serializedHrp, serializedChainID, serializedPath]), [LedgerError.NoErrors])
      .then(processGetAddrResponse, processErrorResponse)
  }

  async getAddressAndPubKey(path: string, show: boolean, hrp?: string, chainid?: string) {
    return this._pubkey(path, show, hrp, chainid)
  }

  private async _xpub(path: string, show: boolean, hrp?: string, chainid?: string): Promise<ResponseXPub> {
    const p1 = show ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE
    const serializedPath = serializePath(path)
    const serializedHrp = serializeHrp(hrp)
    const serializedChainID = serializeChainID(chainid)

    return this.transport
      .send(CLA, INS.GET_EXTENDED_PUBLIC_KEY, p1, 0, Buffer.concat([serializedHrp, serializedChainID, serializedPath]), [
        LedgerError.NoErrors,
      ])
      .then(processGetXPubResponse, processErrorResponse)
  }

  async getExtendedPubKey(path: string, show: boolean, hrp?: string, chainid?: string) {
    return this._xpub(path, show, hrp, chainid)
  }

  private async _walletId(show: boolean): Promise<ResponseWalletId> {
    const p1 = show ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE

    return this.transport.send(CLA, INS.WALLET_ID, p1, 0).then(response => {
      const errorCodeData = response.slice(-2)
      const returnCode = (errorCodeData[0] * 256 + errorCodeData[1]) as LedgerError

      return {
        returnCode,
        errorMessage: errorCodeToString(returnCode),
        id: response.slice(0, 6),
      }
    }, processErrorResponse)
  }

  async getWalletId() {
    return this._walletId(false)
  }

  async showWalletId() {
    return this._walletId(true)
  }

  signEVMTransaction(
    path: string,
    rawTxHex: string,
    resolution?: LedgerEthTransactionResolution | null,
  ): Promise<{
    s: string
    v: string
    r: string
  }> {
    return this.eth.signTransaction(path, rawTxHex, resolution)
  }

  getETHAddress(
    path: string,
    boolDisplay?: boolean,
    boolChaincode?: boolean,
  ): Promise<{
    publicKey: string
    address: string
    chainCode?: string
  }> {
    return this.eth.getAddress(path, boolDisplay, boolChaincode)
  }

  getAppConfiguration(): Promise<{
    arbitraryDataEnabled: number
    erc20ProvisioningNecessary: number
    starkEnabled: number
    starkv2Supported: number
    version: string
  }> {
    return this.eth.getAppConfiguration()
  }

  async provideERC20TokenInformation(
    ticker: string,
    contractName: string,
    address: string,
    decimals: number,
    chainId: number,
  ): Promise<boolean> {
    // Calculate lengths
    const tickerLength = Buffer.byteLength(ticker)
    const contractNameLength = Buffer.byteLength(contractName)

    // Create a buffer with the exact size needed
    const buffer = Buffer.alloc(1 + tickerLength + 1 + contractNameLength + 20 + 4 + 4)

    let offset = 0

    // Ticker length and ticker
    buffer.writeUInt8(tickerLength, offset)
    offset += 1
    buffer.write(ticker, offset)
    offset += tickerLength

    // Contract name length and contract name
    buffer.writeUInt8(contractNameLength, offset)
    offset += 1
    buffer.write(contractName, offset)
    offset += contractNameLength

    // Address (20 bytes, hex string needs to be parsed)

    var addr_offset = 0
    if (address.startsWith('0x')) {
      addr_offset = 2
    }

    // Slice to remove '0x'
    const addressBuffer = Buffer.from(address.slice(addr_offset), 'hex')
    addressBuffer.copy(buffer, offset)
    offset += 20

    // Decimals (4 bytes, big endian)
    buffer.writeUInt32BE(decimals, offset)
    offset += 4

    // Chain ID (4 bytes, big endian)
    buffer.writeUInt32BE(chainId, offset)
    offset += 4

    return this.eth.provideERC20TokenInformation(buffer.toString('hex'))
  }

  async provideNFTInformation(collectionName: string, contractAddress: string, chainId: bigint): Promise<boolean> {
    const NAME_LENGTH_SIZE = 1
    const HEADER_SIZE = TYPE_SIZE + VERSION_SIZE + NAME_LENGTH_SIZE
    const KEY_ID_SIZE = 1
    const PROD_NFT_METADATA_KEY = 1

    const collectionNameLength = Buffer.byteLength(collectionName, 'utf8')

    if (collectionNameLength > COLLECTION_NAME_MAX_LEN) {
      throw new Error(`Collection name exceeds maximum allowed length of ${COLLECTION_NAME_MAX_LEN}`)
    }

    // We generate a fake signature, because verification is disabled
    // in the app.
    const fakeDerSignature = this._generateFakeDerSignature()

    const buffer = Buffer.alloc(
      HEADER_SIZE +
        collectionNameLength +
        ADDRESS_LENGTH +
        CHAIN_ID_SIZE +
        KEY_ID_SIZE +
        ALGORITHM_ID_SIZE +
        SIGNATURE_LENGTH_SIZE +
        fakeDerSignature.length,
    )

    let offset = 0

    buffer.writeUInt8(TYPE_1, offset)
    offset += TYPE_SIZE

    buffer.writeUInt8(VERSION_1, offset)
    offset += VERSION_SIZE

    buffer.writeUInt8(collectionNameLength, offset)
    offset += NAME_LENGTH_SIZE

    buffer.write(collectionName, offset, 'utf8')
    offset += collectionNameLength

    Buffer.from(contractAddress.slice(2), 'hex').copy(buffer, offset) // Remove '0x' from address
    offset += ADDRESS_LENGTH

    buffer.writeBigUInt64BE(chainId, offset)
    offset += CHAIN_ID_SIZE

    buffer.writeUInt8(PROD_NFT_METADATA_KEY, offset) // Assume production key for simplicity
    offset += KEY_ID_SIZE

    buffer.writeUInt8(ALGORITHM_ID_1, offset) // Assume a specific algorithm for signature or hash
    offset += ALGORITHM_ID_SIZE

    buffer.writeUInt8(fakeDerSignature.length, offset)
    offset += SIGNATURE_LENGTH_SIZE

    fakeDerSignature.copy(buffer, offset)

    return this.eth.provideNFTInformation(buffer.toString('hex'))
  }

  _generateFakeDerSignature(): Buffer {
    const fakeSignatureLength = 70
    const fakeDerSignature = Buffer.alloc(fakeSignatureLength)

    // Fill the buffer with random bytes
    for (let i = 0; i < fakeSignatureLength; i++) {
      fakeDerSignature[i] = Math.floor(Math.random() * 256)
    }

    return fakeDerSignature
  }

  // We assume pluginName is ERC721 for Nft tokens
  async setPlugin(contractAddress: string, methodSelector: string, chainId: bigint): Promise<boolean> {
    const KEY_ID = 2
    const PLUGIN_NAME_LENGTH_SIZE = 1
    const KEY_ID_SIZE = 1
    const PLUGIN_NAME = 'ERC721'

    const pluginNameBuffer = Buffer.from(PLUGIN_NAME, 'utf8')
    const pluginNameLength = pluginNameBuffer.length

    const contractAddressBuffer = Buffer.from(contractAddress.slice(2), 'hex')
    const methodSelectorBuffer = Buffer.from(methodSelector.slice(2), 'hex')

    // We generate a fake signature, because verification is disabled
    // in the app.
    const signatureBuffer = this._generateFakeDerSignature()
    const signatureLength = signatureBuffer.length

    const buffer = Buffer.alloc(
      TYPE_SIZE +
        VERSION_SIZE +
        PLUGIN_NAME_LENGTH_SIZE +
        pluginNameLength +
        contractAddressBuffer.length +
        methodSelectorBuffer.length +
        CHAIN_ID_SIZE +
        KEY_ID_SIZE +
        ALGORITHM_ID_SIZE +
        SIGNATURE_LENGTH_SIZE +
        signatureLength,
    )

    let offset = 0

    buffer.writeUInt8(TYPE_1, offset)
    offset += TYPE_SIZE

    buffer.writeUInt8(VERSION_1, offset)
    offset += VERSION_SIZE

    buffer.writeUInt8(pluginNameLength, offset)
    offset += PLUGIN_NAME_LENGTH_SIZE

    pluginNameBuffer.copy(buffer, offset)
    offset += pluginNameLength

    contractAddressBuffer.copy(buffer, offset)
    offset += contractAddressBuffer.length

    methodSelectorBuffer.copy(buffer, offset)
    offset += methodSelectorBuffer.length

    buffer.writeBigUInt64BE(BigInt(chainId), offset)
    offset += CHAIN_ID_SIZE

    // use default key_id
    buffer.writeUInt8(KEY_ID, offset)
    offset += KEY_ID_SIZE

    // use default algorithm
    buffer.writeUInt8(ALGORITHM_ID_1, offset)
    offset += ALGORITHM_ID_SIZE

    buffer.writeUInt8(signatureLength, offset)
    offset += SIGNATURE_LENGTH_SIZE

    signatureBuffer.copy(buffer, offset)

    return this.eth.setPlugin(buffer.toString('hex'))
  }

  async clearSignTransaction(
    path: string,
    rawTxHex: string,
    resolutionConfig: ResolutionConfig,
    throwOnError = false,
  ): Promise<{ r: string; s: string; v: string }> {
    return this.eth.clearSignTransaction(path, rawTxHex, resolutionConfig, throwOnError)
  }

  async signEIP712Message(path: string, jsonMessage: EIP712Message, fullImplem = false): Promise<{ v: number; s: string; r: string }> {
    return this.eth.signEIP712Message(path, jsonMessage, fullImplem)
  }

  async signEIP712HashedMessage(
    path: string,
    domainSeparatorHex: string,
    hashStructMessageHex: string,
  ): Promise<{ v: number; s: string; r: string }> {
    return this.eth.signEIP712HashedMessage(path, domainSeparatorHex, hashStructMessageHex)
  }
}

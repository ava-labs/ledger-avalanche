/** ******************************************************************************
 *  (c) 2026 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 ******************************************************************************* */

// Regression test for the v1.4.6 → v1.4.13 path-prefix fix.
//
// v1.4.6 introduced `verify_avax_root_path` which rejected any AVAX-signing
// root whose coin type was not 9000'. That broke real wallets (Core Wallet)
// which correctly sign CoreEth atomic transactions (EvmExport / EvmImport)
// with the C-chain account root `m/44'/60'/account'`, because the funds being
// moved on the C-chain side are owned by a key derived under coin type 60'.
//
// v1.4.13 relaxes the check to accept either 9000' or 60' at the root. This
// test signs the same C-chain Import/Export vectors used in c_sign.test.ts
// but with `m/44'/60'/0'` instead of `m/44'/9000'/0'`, and asserts the
// signature verifies against the correct C-chain public keys.

import Zemu from '@zondax/zemu'
import { C_CHAIN_ROOT_PATH, defaultOptions, models } from './common'
import AvalancheApp from '@zondax/ledger-avalanche-app'
import { C_IMPORT_FROM_X, C_EXPORT_TO_X } from './c_chain_vectors'

// @ts-ignore
import secp256k1 from 'secp256k1/elliptic'
// @ts-ignore
import crypto from 'crypto'

const SIGN_TEST_DATA = [
  { name: 'c_import_from_x_coreth_root', op: C_IMPORT_FROM_X },
  { name: 'c_export_to_x_coreth_root', op: C_EXPORT_TO_X },
]

jest.setTimeout(200_000)

describe.each(models)('C_Sign_CorethRoot[%s]; sign', function (m) {
  test.each(SIGN_TEST_DATA)('sign c-chain $name with m/44\'/60\'/0\'', async function ({ name, op }) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new AvalancheApp(sim.getTransport())
      const msg = op

      const testcase = `${m.prefix.toLowerCase()}-sign-${name}`

      const signers = ['0/1', '5/8']
      const respReq = app.sign(C_CHAIN_ROOT_PATH, signers, msg)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', testcase)

      const resp = await respReq

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signatures')
      expect(resp.signatures?.size).toEqual(signers.length)

      const hash = crypto.createHash('sha256')
      const msgHash = Uint8Array.from(hash.update(msg).digest())

      for (const signer of signers) {
        const path = `${C_CHAIN_ROOT_PATH}/${signer}`
        const resp_addr = await app.getAddressAndPubKey(path, false)
        const pk = Uint8Array.from(resp_addr.publicKey)
        const signatureRS = Uint8Array.from(resp.signatures?.get(signer)!).slice(0, -1)

        const signatureOk = secp256k1.ecdsaVerify(signatureRS, msgHash, pk)
        expect(signatureOk).toEqual(true)
      }
    } finally {
      await sim.close()
    }
  })
})

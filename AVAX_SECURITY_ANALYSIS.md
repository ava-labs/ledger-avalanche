# AVAX Security Review — Analysis & Remediation Plan

## Summary

**12 FIXED · 9 No fix needed**

| ID     | Reported     | Assessed      | Status        | Primary files |
| ------ | ------------ | ------------- | ------------- | ------------- |
| F-001  | High         | High          | FIXED         | `apdu_wrapper.rs` |
| P2-001 | High         | High          | FIXED         | `u256.rs`, `coreth/native/legacy.rs` |
| P3-012 | High         | High          | FIXED         | `transactions.rs` |
| P3-001 | Medium-High  | Medium-High   | FIXED         | `address.rs`, `error.rs`, 5× `outputs/*.rs`, `pchain_owner.rs`, `inputs/secp_transfer_input.rs` |
| P8-001 | Medium-High  | Medium-High   | FIXED         | `validator/weight_type.rs` |
| F-007  | Medium       | Medium        | FIXED         | `handlers/avax.rs`, `handlers/avax/{signing,sign_hash,message}.rs` |
| V-001  | Medium       | Medium        | FIXED         | `handlers/eth.rs`, `handlers/eth/{signing,personal_msg,public_key}.rs`, `constants.rs` |
| P2-014 | Medium       | Medium        | FIXED         | `coreth/native/{legacy,eip2930}.rs` |
| P2-015 | Medium       | Medium        | FIXED         | `coreth/data/{erc20,erc721}.rs` |
| P3-002 | Low-Medium   | Low-Medium    | FIXED         | 5× `outputs/*.rs`, `pchain_owner.rs`, `inputs/secp_transfer_input.rs` |
| P3-014 | Low-Medium   | Low-Medium    | FIXED         | `parser/message.rs` |
| LA-001 | High         | High          | FIXED         | `addressed_call_payloads.rs`, `addressed_call.rs` |
| P4-001 | High         | Informational | No fix needed | `outputs.rs`, `secp_transfer_output.rs`, `transfer.rs` |
| P5-001 | High         | Informational | No fix needed | `outputs/secp_transfer_output.rs` |
| P5-002 | High         | Informational | No fix needed | `secp_output_owners.rs`, `pvm/{add_validator,add_delegator}.rs` |
| P6-001 | High         | Informational | No fix needed | `outputs/nft_transfer_output.rs`, `operations/nft_{transfer,mint}_operation.rs` |
| P7-001 | High         | Informational | No fix needed | `avm/create_asset.rs`, `initial_state.rs` |
| P7-002 | High         | Informational | No fix needed | `operations/secp_mint_operation.rs`, `outputs/secp_mint_output.rs` |
| P7-003 | Medium-High  | Informational | No fix needed | `pvm/create_chain_tx.rs` |
| P2-013 | Medium       | Informational | No fix needed | `handlers/avax/sign_hash.rs` |
| P8-002 | Medium       | Informational | No fix needed | `subnet_auth.rs`, `pvm/{add_subnet_validator,create_chain_tx}.rs` |

> **Reported** = severity from the source review.
> **Assessed** = our post-verification classification.
> *No fix needed* findings are reclassified to **Informational** — the residual risk is accepted by design.

---

## Themes

1. **Display/sign parity (CWE-451)** — fields parsed into the signing hash but not counted or rendered in the UI. Dominant theme in the source review (11 of 19 findings). Most are accepted as intentional product decisions: the device's review surface is address-based, and surfacing every signed field would add noise without changing the signer's approve/reject judgement.
2. **Parser strictness** — trailing bytes / remainder not required empty, allowing hidden suffixes in the signed payload. All instances closed.
3. **Counter widths** — `u8` UI item counts could wrap when address lists were unbounded. Closed by capping address lists at parse time.
4. **APDU / handler state** — bounds checks against wrong length and path validation that only checked depth. Closed.

---

## Findings — FIXED

### F-001 — APDU payload bounds against full buffer, not received length

> **CWE-125** · **Severity:** High · **Status:** FIXED

**Files:** `app/rust/src/utils/apdu_wrapper.rs`, integration-test plumbing updates.

**Analysis.** `ApduBufferRead::new` validated `buf.len() >= rx` but then dropped `rx`, so `payload()` bounded `Lc` against the full backing buffer rather than the received length. A host could advertise an inflated `Lc` and have the reader hand out stale bytes from the rest of the buffer (the SDK reuses one buffer for request and response). Fixed by storing `rx: usize` on the reader and bounding `payload()` against it; `write()` keeps the full buffer because responses can legitimately exceed `rx`.

**Regression coverage.** Exact-fit, larger-buffer-smaller-rx, stale-read rejection (host claims `Lc = 200` with `rx = 5`), off-by-one past `rx`, and empty-payload cases.

---

### P2-001 — Coreth `is_zero()` predicate is inverted; hides native AVAX value on asset calls

> **CWE-451** · **Severity:** High · **Status:** FIXED

**Files:** `app/rust/src/handlers/eth/utils/u256.rs`, `parser/coreth/native/legacy.rs`.

**Analysis.** `BorrowedU256::is_zero` was `iter().all(|v| *v != 0)` — the inverse of the documented semantics. Coreth asset-call parsers used it to reject native AVAX value on asset calls, so any non-trivial value (e.g. `0x01`) slipped through and was signed without being shown. Fixed by flipping the predicate to `*v == 0`.

**Regression coverage.** Unit tests for empty / all-zero / single-nonzero / all-nonzero / mixed byte sequences, plus a Legacy asset-transfer parser test that feeds a non-zero outer value and expects rejection.

---

### P3-012 — Native transaction parser accepts trailing bytes

> **CWE-20** · **Severity:** High · **Status:** FIXED

**Files:** `app/rust/src/parser/transactions.rs`, plus test-vector cleanup to strip SignedTx `Credentials` that previously relied on the lax remainder handling.

**Analysis.** `Transaction::new_into` parsed the codec and the variant transaction but ignored the variant parser's remainder. Per the Avalanche txn-format spec, the bytes signed by the device are `CodecID + UnsignedTx`; credentials belong to the SignedTx wrapper and must not be present in what the device hashes. Fixed by requiring the variant parser's remainder to be empty.

**Regression coverage.** Appends a zero byte to a known-good Transfer fixture and expects rejection. Three fixtures (one JSON + matching `.rs`, one Zemu, plus the `set_auto_renewed_validator_config` JSON and Zemu pair) were trimmed to remove credential bytes that had been silently tolerated.

---

### P3-001 — Native transaction UI item counts truncate to `u8`

> **CWE-190** · **Severity:** Medium-High · **Status:** FIXED

**Files:** `app/rust/src/parser/address.rs`, `parser/error.rs`, `outputs/{secp_transfer_output,secp_mint_output,secp_output_owners,nft_transfer_output,nft_mint_output}.rs`, `parser/pchain_owner.rs`, `inputs/secp_transfer_input.rs`.

**Analysis.** Per-output `self.addresses.len() as u8` truncated silently when `addr_len` exceeded 255, and aggregate display-item math then lost reviewability. Fixed by introducing `MAX_ADDRESSES = 64` and rejecting `addr_len > MAX_ADDRESSES` (new `ParserError::TooManyAddresses`) at parse time in every address-list site, before any `as u8` cast. With the per-output cap enforced, `base_outputs_num_items` and the transaction-level `checked_add!` macro already detect aggregate overflow and return `ViewError::Unknown`, so UI truncation is no longer reachable.

**Regression coverage.** `parse_secp256k1_output_rejects_too_many_addresses` asserts `ParserError::TooManyAddresses` on `addr_len = 65`.

---

### P8-001 — AddSubnetValidator weight rendered as AVAX stake

> **CWE-451** · **Severity:** Medium-High · **Status:** FIXED

**Files:** `app/rust/src/parser/validator.rs`, `app/rust/src/parser/validator/weight_type.rs`, `pvm/add_subnet_validator.rs:34`.

**Analysis.** `AddSubnetValidatorTx` previously reused the validator/delegator render path that formats the field as `Total stake(AVAX)`, but `AddSubnetValidator` carries a subnet weight (raw integer), not a stake amount. The repo now distinguishes a `Weight` type (label `"Weight"`, raw `u64_to_str`) from `Stake` (label `"Total stake(AVAX)"`, `nano_avax_to_fp_str`), with `AddSubnetValidatorTx` using `Validator<'b, Weight>`.

**Verification.** Snapshot `tx_ui@add_subnet_validator.json.snap:11` confirms `"Weight": "54321"` (raw integer, not AVAX-formatted).

---

### F-007 — Path validation checks depth but not coin type or hardening

> **CWE-285** · **Severity:** Medium · **Status:** FIXED

**Files:** `app/rust/src/handlers/avax.rs` (new `verify_avax_root_path`), `handlers/avax/{signing,sign_hash,message}.rs`.

**Analysis.** Every AVAX-side signing entry validated only `components().len() == 3`, never the coin-type (`9000'`) or whether components were hardened. A host could request signatures from non-AVAX paths while the device displayed a normal AVAX review — classic path confusion. Fixed by centralising a `verify_avax_root_path` helper that asserts depth, the `44' / 9000'` prefix, and hardening on all three components, and routing every signing entry through it.

**Regression coverage.** Unit tests for the canonical root and each rejection case (wrong depth, wrong purpose, wrong coin type, each unhardened component).

---

### V-001 — ETH handlers accepted BIP32 paths under any coin type

> **CWE-285** · **Severity:** Medium · **Status:** FIXED
>
> **Source:** variant hunt follow-up to F-007. Not part of the original 9-pass review.

**Files:** `app/rust/src/handlers/eth.rs` (new `verify_coreth_root_path`), `handlers/eth/{public_key,signing,personal_msg}.rs`, `constants.rs`.

**Analysis.** While F-007 enforced `m/44'/9000'/account'` on the AVAX-native signing entries, the ETH-side handlers (`GetPublicKey`, `Sign`, `PersonalMsg`) still used `parse_bip32_eth` without any prefix validation. A host could request address display, transaction signatures, or personal-message signatures under any BIP32 path — including AVAX native (`44'/9000'`) or unhardened roots — while the device rendered a normal Ethereum review. The ETH review screens only show `"Address: 0x..."` or tx fields, not the derivation path, so there was no user-visible fallback defence. Fixed by adding `verify_coreth_root_path`, which asserts depth in [3, 5], the `44' / 60'` prefix, and hardening on the first three components (purpose / coin type / account). Change and index are left flexible so standard BIP44 Ethereum paths (`m/44'/60'/0'/0/n`) are still accepted.

**Regression coverage.** Ten unit tests: account-only root accepted, Zemu 4-component and MetaMask-style 5-component paths accepted; rejections for too-short, too-long, AVAX coin type (9000'), wrong purpose, and each unhardened first-three component.

---

### P2-014 — Coreth Legacy/EIP-2930 parsers ignore trailing RLP fields

> **CWE-20** · **Severity:** Medium · **Status:** FIXED

**Files:** `app/rust/src/parser/coreth/native/legacy.rs`, `native/eip2930.rs`.

**Analysis.** Both parsers returned `Ok(rem)` after their last expected RLP field without enforcing full consumption (EIP-1559 already did). Any extra item appended inside the transaction list was signed but never displayed. Fixed by requiring an empty remainder in both parsers.

**Regression coverage.** Per variant, append a single `0x01` item inside the list and expect rejection.

---

### P2-015 — ERC20 / ERC721 fixed-arity calldata carries hidden suffix bytes

> **CWE-20** · **Severity:** Medium · **Status:** FIXED

**Files:** `app/rust/src/parser/coreth/data/erc20.rs`, `erc721.rs`.

**Analysis.** ERC20 (`transfer`, `transferFrom`, `approve`) and ERC721 (`transferFrom`, `approve`, `setApprovalForAll`) consumed their fixed-arity 32-byte arguments and returned the calldata remainder without enforcing it was empty — the dispatch then discarded that remainder, so trailing calldata was signed but never displayed. Fixed by requiring an empty remainder in each method's parser; ERC721 `safeTransferFrom(...,bytes)` is intentionally untouched because its `bytes data` parameter is legitimately variable-length.

**Regression coverage.** Each fixed-arity method has paired tests — exact-length calldata accepted, same calldata plus one trailing byte rejected.

---

### P3-002 — Address-list byte length can wrap on 32-bit targets

> **CWE-190** · **Severity:** Low-Medium · **Status:** FIXED (bundled with P3-001)

**Files:** same five output parsers plus `pchain_owner.rs` and `inputs/secp_transfer_input.rs`.

**Analysis.** `addr_len as usize * ADDRESS_LEN` could wrap on 32-bit targets when `addr_len` was a malicious `u32`. Fixed by guarding every `take(...)` with `(addr_len as usize).checked_mul(ADDRESS_LEN)` returning `ParserError::ValueOutOfRange` on overflow. The new `MAX_ADDRESSES` cap (P3-001) makes overflow structurally impossible on any target; `checked_mul` is retained as defense-in-depth so the guarantee is local to each parser.

---

### P3-014 — Personal message signing page count capped at 255

> **CWE-451** · **Severity:** Low-Medium · **Status:** FIXED

**Files:** `app/rust/src/parser/message.rs`.

**Analysis.** `calculate_chunk_count` had a silent `.min(255) as u8` clamp, so a personal message that needed more than 255 chunks would be partially displayed yet fully signed. Fixed by changing the function to return `Result<u8, ParserError>` using `u8::try_from(chunks)`, propagating `ParserError::InvalidMessageSize` so an oversized payload is rejected at parse time rather than signed with an invisible tail.

**Regression coverage.** ASCII over-budget rejection, non-ASCII over-budget rejection, exact-fit 255-chunk message accepted.

---

### LA-001 — AddressedCall trailing bytes (audit finding from `ledger-app-audit`)

> **CWE-20** · **Severity:** High · **Status:** FIXED

**Files:** `app/rust/src/parser/addressed_call_payloads.rs`, `app/rust/src/parser/addressed_call.rs`.

**Analysis.** The dispatcher `AddressedCallPayload::from_payload` discarded the inner message's parser remainder with `let _ = …from_bytes_into(rem, &mut msg)?;` for both `RegisterL1ValidatorMessage` and `SetL1ValidatorWeightMessage`. `AddressedCall::from_bytes_into` similarly read the declared `payload_size` field and threw it away (`let (rem, _) = be_u32(rem)?;`), then handed all remaining bytes to the dispatcher and returned `Ok(&[])` falsely claiming full consumption. Net effect: trailing bytes inside the AddressedCall payload region were covered by the signing hash without being parsed or displayed — the same display/sign parity break as P3-012/P2-014/P2-015.

The avalanchego reference codec (`vms/codec/manager.go`) errors with `ErrExtraSpace` when input bytes are not fully consumed — i.e. trailing bytes inside any declared payload region are malformed per spec.

Fixed by:
- `addressed_call_payloads.rs:148, 154` — capture the inner parser remainder and return `ParserError::UnexpectedData` if it's non-empty.
- `addressed_call.rs:46-49, 57` — slice exactly `payload_size` bytes for the inner payload (`take(payload_size as usize)`), pass the bounded slice to the dispatcher (which then enforces the strict-consume check above), and return the actual outer remainder rather than `Ok(&[])`.

---

## Findings — No fix needed

### P4-001 — Native transaction summaries treat arbitrary asset IDs as AVAX

> **CWE-451** · **Severity:** High → Informational · **Status:** No fix needed

**Files:** `app/rust/src/parser/outputs.rs:41-124`, `outputs/secp_transfer_output.rs:120` (hard-coded `" AVAX to "`), `transactions/base_tx_fields.rs:79-94`, `transactions/transfer.rs:99-172`.

**Analysis.** Every output amount is rendered with the suffix `" AVAX to "`, and `Fee(AVAX)` is computed by subtracting outputs from inputs without partitioning by `asset_id`. The on-device review model trusts the user to verify the from/to addresses, which are shown per output regardless of the asset. The asset symbol is therefore advisory; the worst case is a misleading unit on the amount, not silent fund diversion to an unintended destination. No remediation required; ship as-is.

---

### P5-001 — SECP transfer outputs hide signed locktime and threshold

> **CWE-451** · **Severity:** High → Informational · **Status:** No fix needed

**Files:** `app/rust/src/parser/outputs/secp_transfer_output.rs:33-135`.

**Analysis.** `locktime` and `threshold` are stored but not surfaced. The AVAX team reviewed the on-device display surface and deliberately omitted both fields from SECP transfer output screens — surfacing them would add review noise without changing the signer's approve/reject decision; the recipient address remains the trusted review item.

---

### P5-002 — Reward-owner screens hide locktime and threshold

> **CWE-451** · **Severity:** High → Informational · **Status:** No fix needed

**Files:** `app/rust/src/parser/outputs/secp_output_owners.rs:64-138`, `transactions/pvm/add_validator.rs:115-388`, `pvm/add_delegator.rs:107-378`.

**Analysis.** `locktime` is now conditionally rendered when non-zero, but `threshold` remains omitted from validator/delegator staking screens. The visible "Rewards to" address list is the intended review surface; the AVAX team reviewed and accepts that the threshold field is not shown.

---

### P6-001 — NFT mint/transfer operations hide locktime and threshold

> **CWE-451** · **Severity:** High → Informational · **Status:** No fix needed

**Files:** `app/rust/src/parser/outputs/nft_transfer_output.rs:41-198`, `operations/nft_transfer_operation.rs:59-90`, `operations/nft_mint_operation.rs:59-91`.

**Analysis.** `locktime` and `threshold` are stored but not rendered in NFT mint/transfer operation screens. Same review-surface stance as P5-001 — group ID, payload, and owner addresses are the intended approve/reject signal.

---

### P7-001 — CreateAsset hides initial allocations and mint authorities

> **CWE-451** · **Severity:** High → Informational · **Status:** No fix needed

**Files:** `app/rust/src/parser/transactions/avm/create_asset.rs:36-175`, `app/rust/src/parser/initial_state.rs:43-62`.

**Analysis.** `initial_states` is parsed but the review is fixed at five items (description, name, symbol, denomination, fee). The AVAX team reviewed the surface and deliberately omits the allocation/mint-authority breakdown — the visible asset metadata is the intended review item.

---

### P7-002 — SECPMintOperation hides the new mint-output authority

> **CWE-451** · **Severity:** High → Informational · **Status:** No fix needed

**Files:** `app/rust/src/parser/operations/secp_mint_operation.rs:36-114`, `app/rust/src/parser/outputs/secp_mint_output.rs:31-148`.

**Analysis.** `mint_output` (future mint authority) is parsed but not rendered; only the immediate `transfer_output` is shown by design. Same review-surface stance as P5-001/P6-001.

---

### P7-003 — CreateChain hides signed FX IDs

> **CWE-451** · **Severity:** Medium-High → Informational · **Status:** No fix needed

**Files:** `app/rust/src/parser/transactions/pvm/create_chain_tx.rs:38-190`.

**Analysis.** `fx_id` is parsed but the review item count is hardcoded at six (description, subnet ID, chain name, VM ID, genesis hash, fee). FX IDs are not considered relevant to the signer's approve/reject decision; surfacing them would add review noise. Same stance as P8-002.

**Residual hardening note.** `create_chain_tx.rs:100` still uses `num_fx_id as usize * FX_ID_LEN` without a cap; bounding it at parse time (same pattern as P3-001/P3-002) is worthwhile independently of the display question.

---

### P2-013 — SignHash continuation APDUs underconstrained after approval

> **CWE-371** · **Severity:** Medium → Informational · **Status:** No fix needed

**Files:** `app/rust/src/handlers/avax/sign_hash.rs:223-290`.

**Analysis.** The audit framed this as a chunk-upload state-machine bug, but the SignHash protocol isn't a chunked upload — the hash plus path suffix is small enough to fit in one APDU. After `FIRST_MESSAGE` review, non-FIRST p1 values request *additional signatures over the already-reviewed hash* using the path suffix in each APDU's `cdata` — that's the multisig signer-iteration UX, not chunked input. The strict guarantees we need (no signature without review, signed hash equals reviewed hash, state eventually clears) are all enforced. Locking signer-count at approval time would actively break the multi-signer flow that needs each signer's path delivered just-in-time. No remediation required.

---

### P8-002 — Subnet authorization indices never displayed

> **CWE-451** · **Severity:** Medium → Informational · **Status:** No fix needed

**Files:** `app/rust/src/parser/subnet_auth.rs:31-64`, `transactions/pvm/add_subnet_validator.rs:67-123`, `pvm/create_chain_tx.rs:109-196`.

**Analysis.** `SubnetAuth.sig_indices` is parsed but deliberately omitted from the device review. The hardcoded item counts in containing transactions are intentional — signature-index slots are not considered relevant to the signer's approve/reject decision, and surfacing them would add review noise without informing intent.

**Residual hardening note.** `subnet_auth.rs:55` still uses `num_indices as usize * U32_SIZE` without a cap; bounding it at parse time (same pattern as P3-001/P3-002) is worthwhile independently of the display question.

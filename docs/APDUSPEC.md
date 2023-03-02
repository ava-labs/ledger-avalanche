# Avalanche App

## General structure

The app provides support for 2 sets of instructions, the Avalanche set and the Ethereum set.
The Ethereum set is aimed at providing compatibility with EVM wallets, 
as such the API is the same as the Ethereum App, with the CLA being 0xE0,
whilst the Avalanche app normally uses 0x80 for the CLA.

The general structure of commands and responses is as follows:

#### Commands

| Field   | Type     | Content                | Note      |
|:--------|:---------|:-----------------------|-----------|
| CLA     | byte (1) | Application Identifier | 0x80/0xE0 |
| INS     | byte (1) | Instruction ID         |           |
| P1      | byte (1) | Parameter 1            |           |
| P2      | byte (1) | Parameter 2            |           |
| L       | byte (1) | Bytes in payload       |           |
| PAYLOAD | byte (L) | Payload                |           |

#### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

#### Return codes

| Return code | Description              |
|-------------|--------------------------|
| 0x6400      | Execution Error          |
| 0x6700      | Wrong Length             |
| 0x6982      | Empty buffer             |
| 0x6983      | Output buffer too small  |
| 0x6A80      | Data Invalid             |
| 0x6985      | Conditions not satisfied |
| 0x6986      | Command not allowed      |
| 0x6B00      | Invalid P1/P2            |
| 0x6D00      | INS not supported        |
| 0x6E00      | CLA not supported        |
| 0x6F00      | Unknown                  |
| 0x9000      | Success                  |
| 0x9001      | Busy                     |

---

## Command definition

### INS_GET_VERSION

#### Command

| Field | Type     | Content                | Expected |
|-------|----------|------------------------|----------|
| CLA   | byte (1) | Application Identifier | 0x80     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | ignored  |

#### Response

| Field     | Type     | Content          | Note                            |
| --------- | -------- | ---------------- | ------------------------------- |
| TEST      | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR     | byte (1) | Version Major    |                                 |
| MINOR     | byte (1) | Version Minor    |                                 |
| PATCH     | byte (1) | Version Patch    |                                 |
| LOCKED    | byte (1) | Device is locked |                                 |
| TARGET ID | byte (4) | Target ID        |                                 |
| SW1-SW2   | byte (2) | Return code      | see list of return codes        |

### INS_GET_WALLET_ID

#### Command

| Field | Type     | Content                   | Expected |
|-------|----------|---------------------------|----------|
| CLA   | byte (1) | Application Identifier    | 0x80     |
| INS   | byte (1) | Instruction ID            | 0x01     |
| P1    | byte (1) | Request User confirmation | No = 0   |
| P2    | byte (1) | Parameter 2               | ignored  |
| L     | byte (1) | Bytes in payload          | ignored  |

#### Response

| Field     | Type     | Content     | Note                     |
|-----------|----------|-------------|--------------------------|
| WALLET_ID | byte (6) | Wallet ID   |                          |
| SW1-SW2   | byte (2) | Return code | see list of return codes |

### INS_GET_PUBLIC_KEY

#### Command

If the HRPLen is 0, then the default HRP of 'avax' is used.
If the ChainIDLen is 0, then the default ChainID of 32 zero bytes (P-Chain's)

| Field      | Type              | Content                   | Expected                 |
|------------|-------------------|---------------------------|--------------------------|
| CLA        | byte (1)          | Application Identifier    | 0x80                     |
| INS        | byte (1)          | Instruction ID            | 0x02                     |
| P1         | byte (1)          | Request User confirmation | No = 0                   |
| P2         | byte (1)          |                           | ignored                  |
| L          | byte (1)          | Bytes in payload          | (depends)                |
| HRPLen     | byte (1)          | Length of HRP             | 0 to 24                  |
| HRP        | byte (HRPLen)     | HRP                       | ?                        |
| ChainIDLen | byte (1)          | Length of ChainID         | 0 OR 32                  |
| ChainID    | byte (ChainIDLen) | ChainID                   | ?                        |
| PathN      | byte (1)          | Number of path components | ? (typically 4, up to 6) |
| Path[0]    | byte (4)          | Derivation Path Data      | 0x8000002c               |
| Path[1]    | byte (4)          | Derivation Path Data      | 0x80002328               |
| Path[2]    | byte (4)          | Derivation Path Data      | ?                        |
| Path[3]    | byte (4)          | Derivation Path Data      | ?                        |
| Path[4]    | byte (4)          | Derivation Path Data      | ?                        |
| Path[5]    | byte (4)          | Derivation Path Data      | ?                        |

#### Response

| Field     | Type      | Content          | Note                     |
|-----------|-----------|------------------|--------------------------|
| PK_LEN    | byte (1)  | Bytes in PKEY    |                          |
| PKEY      | byte (??) | Public key bytes | Compressed public key    |
| PKEY_HASH | byte (20) | Public key hash  | Ripemd160(Sha256(PKEY))  |
| ADDR      | byte (??) | Address          | CB58 encoded address     |
| SW1-SW2   | byte (2)  | Return code      | see list of return codes |

### INS_GET_EXTENDED_PUBLIC_KEY

#### Command

If the HRPLen is 0, then the default HRP of 'avax' is used.
If the ChainIDLen is 0, then the default ChainID of 32 zero bytes (P-Chain's)

| Field      | Type              | Content                   | Expected                 |
|------------|-------------------|---------------------------|--------------------------|
| CLA        | byte (1)          | Application Identifier    | 0x80                     |
| INS        | byte (1)          | Instruction ID            | 0x03                     |
| P1         | byte (1)          | Request User confirmation | No = 0                   |
| P2         | byte (1)          |                           | ignored                  |
| L          | byte (1)          | Bytes in payload          | (depends)                |
| HRPLen     | byte (1)          | Length of HRP             | 0 to 24                  |
| HRP        | byte (HRPLen)     | HRP                       | ?                        |
| ChainIDLen | byte (1)          | Length of ChainID         | 0 OR 32                  |
| ChainID    | byte (ChainIDLen) | ChainID                   | ?                        |
| PathN      | byte (1)          | Number of path components | ? (typically 4, up to 6) |
| Path[0]    | byte (4)          | Derivation Path Data      | 0x8000002c               |
| Path[1]    | byte (4)          | Derivation Path Data      | 0x80002328               |
| Path[2]    | byte (4)          | Derivation Path Data      | ?                        |
| Path[3]    | byte (4)          | Derivation Path Data      | ?                        |
| Path[4]    | byte (4)          | Derivation Path Data      | ?                        |
| Path[5]    | byte (4)          | Derivation Path Data      | ?                        |

#### Response

| Field      | Type      | Content          | Note                     |
|------------|-----------|------------------|--------------------------|
| PK_LEN     | byte (1)  | Bytes in PKEY    |                          |
| PKEY       | byte (??) | Public key bytes | Compressed public key    |
| CHAIN_CODE | byte (32) | Chain Code       |                          |
| SW1-SW2    | byte (2)  | Return code      | see list of return codes |

### INS_SIGN_HASH

The app includes a protocol to sign the same message multiple times, as described in this instruction.

#### Command

| Field | Type     | Content                | Expected  |
|-------|----------|------------------------|-----------|
| CLA   | byte (1) | Application Identifier | 0x80      |
| INS   | byte (1) | Instruction ID         | 0x04      |
| P1    | byte (1) | Signature step         | 0 = init  |
|       |          |                        | x = next  |
|       |          |                        | 2 = last  |
| P2    | byte (1) |                        | ignored   |
| L     | byte (1) | Bytes in payload       | (depends) |

##### Init

The first message should contain the root path for the keys to use, as well as the hash to sign.

| Field   | Type      | Content                   | Expected   |
|---------|-----------|---------------------------|------------|
| PathN   | byte (1)  | Number of path components | 3          |
| Path[0] | byte (4)  | Derivation Path Data      | 0x8000002c |
| Path[1] | byte (4)  | Derivation Path Data      | 0x80002328 |
| Path[2] | byte (4)  | Derivation Path Data      | 0x80000000 |
| Hash    | byte (32) | Hash to sign              | ?          |

##### Next

The next N messages should contain the last 2 path elements needed to compute the private key

| Field   | Type      | Content                   | Expected |
|---------|-----------|---------------------------|----------|
| PathN   | byte (1)  | Number of path components | 2        |
| Path[0] | byte (4)  | Derivation Path Data      | ?        |
| Path[1] | byte (4)  | Derivation Path Data      | ?        |

##### Last

Same as next, but also signals the app that no more signatures are to be produced

#### Response

Other than `Init`, which just returns a success code, `Next` and `Last` have the following response:

| Field   | Type      | Content     | Note                     |
|---------|-----------|-------------|--------------------------|
| SIG     | byte (65) | Signature   | signature                |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

## INS_SIGN

The app includes a protocol to upload a large payload in multiple messages, as described in this instruction.

#### Command

| Field | Type     | Content                | Expected  |
|-------|----------|------------------------|-----------|
| CLA   | byte (1) | Application Identifier | 0x80      |
| INS   | byte (1) | Instruction ID         | 0x05      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = next  |
|       |          |                        | 2 = last  |
| P2    | byte (1) |                        | ignored   |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes the root derivation path.

##### Init

| Field       | Type     | Content                   | Expected   |
|-------------|----------|---------------------------|------------|
| PathN       | byte (1) | Number of path components | 3          |
| Path[0]     | byte (4) | Derivation Path Data      | 0x8000002c |
| Path[1]     | byte (4) | Derivation Path Data      | 0x80002328 |
| Path[2]     | byte (4) | Derivation Path Data      | ?          |

##### Add

| Field   | Type     | Content      | Expected |
|---------|----------|--------------|----------|
| ...     | ...      | ...          |          |
| P1      | byte (1) | Payload desc | 1        |
| ...     | ...      | ...          |          |
| Message | bytes    | payload      |          |

The message payload is expected to be prefixed with a list of change paths, once, in the following format. 
Any byte after is understood to be part of the message to sign and will be parsed accordingly.

| Field         | Type     | Content                   | Expected |
|---------------|----------|---------------------------|----------|
| ChangePathN   | byte (4) | Number of change paths    |          |
| ChangePathN-1 | byte (1) | Number of path components | 2        |
| Path[0]       | byte (4) | Derivation Path Data      | ?        |
| Path[1]       | byte (4) | Derivation Path Data      | ?        |
| ChangePathN-2 | byte (1) | Number of path components | 2        |
| Path[0]       | byte (4) | Derivation Path Data      | ?        |
| Path[1]       | byte (4) | Derivation Path Data      |          |
| ...           | ...      | ...                       |          |

##### Last

This signals the app that no more data should be received in regards to this payload.
This will trigger the UI confirmation flow, 
storing the confirmed hash for signing later via [INS_SIGN_HASH], skipping the "Init" step.

| Field | Type     | Content                | Expected |
|-------|----------|------------------------|----------|
| ...   | ...      | ...                    |          |
| P1    | byte (1) | Payload desc           | 2        |
| ...   | ...      | ...                    |          |
| Data  | bytes    | Remaining data to sign |          |

#### Response

| Field    | Type            | Content     | Note                                  |
|----------|-----------------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)        | Return code | see list of return codes              |

## INS_SIGN_MSG

Used to sign an avax personal message. 
The payload should include the header, please see the avax docs for more information. 
Uses the protocol to upload a large payload with multiple messages.

#### Command

| Field | Type     | Content                | Expected  |
|-------|----------|------------------------|-----------|
| CLA   | byte (1) | Application Identifier | 0x80      |
| INS   | byte (1) | Instruction ID         | 0x06      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = next  |
|       |          |                        | 2 = last  |
| P2    | byte (1) |                        | ignored   |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes the root derivation path.

##### Init

| Field       | Type     | Content                   | Expected   |
|-------------|----------|---------------------------|------------|
| PathN       | byte (1) | Number of path components | 3          |
| Path[0]     | byte (4) | Derivation Path Data      | 0x8000002c |
| Path[1]     | byte (4) | Derivation Path Data      | 0x80002328 |
| Path[2]     | byte (4) | Derivation Path Data      | ?          |

##### Add

| Field   | Type     | Content         | Expected |
|---------|----------|-----------------|----------|
| ...     | ...      | ...             |          |
| P1      | byte (1) | Payload desc    | 1        |
| ...     | ...      | ...             |          |
| Message | bytes    | message to sign |          |

##### Last

This signals the app that no more data should be received in regards to this payload.
This will trigger the UI confirmation flow, 
storing the confirmed hash for signing later via [INS_SIGN_HASH], skipping the "Init" step.

| Field | Type     | Content                | Expected |
|-------|----------|------------------------|----------|
| ...   | ...      | ...                    |          |
| P1    | byte (1) | Payload desc           | 2        |
| ...   | ...      | ...                    |          |
| Data  | bytes    | Remaining data to sign |          |

#### Response

| Field    | Type            | Content     | Note                                  |
|----------|-----------------|-------------|---------------------------------------|
| SW1-SW2  | byte (2)        | Return code | see list of return codes              |

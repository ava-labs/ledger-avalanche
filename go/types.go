/*******************************************************************************
*   (c) 2018 - 2022 ZondaX AG
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
********************************************************************************/

package ledger_avalanche_go

import (
	"fmt"
	"github.com/zondax/ledger-go"
)

const (
	CLA     = 0x80
	CLA_ETH = 0xE0

	CHUNK_SIZE = 250
	HASH_LEN   = 32

	PAYLOAD_INIT = 0x00
	PAYLOAD_ADD  = 0x01
	PAYLOAD_LAST = 0x02

	FIRST_MESSAGE = 0x01
	LAST_MESSAGE  = 0x02
	NEXT_MESSAGE  = 0x03

	P1_ONLY_RETRIEVE          = 0x00
	P1_SHOW_ADDRESS_IN_DEVICE = 0x01

	INS_GET_VERSION             = 0x00
	INS_WALLET_ID               = 0x01
	INS_GET_ADDR                = 0x02
	INS_GET_EXTENDED_PUBLIC_KEY = 0x03
	INS_SIGN_HASH               = 0x04
	INS_SIGN                    = 0x05
	INS_SIGN_MSG                = 0x06

	userINSGetVersion       = 0
	userINSSignSECP256K1    = 2
	userINSGetAddrSecp256k1 = 4

	userMessageChunkSize = 250

	HARDENED = 0x80000000
)

type LedgerError int

const (
	U2FUnknown                  LedgerError = 1
	U2FBadRequest               LedgerError = 2
	U2FConfigurationUnsupported LedgerError = 3
	U2FDeviceIneligible         LedgerError = 4
	U2FTimeout                  LedgerError = 5
	Timeout                     LedgerError = 14
	NoErrors                    LedgerError = 0x9000
	DeviceIsBusy                LedgerError = 0x9001
	ErrorDerivingKeys           LedgerError = 0x6802
	ExecutionError              LedgerError = 0x6400
	WrongLength                 LedgerError = 0x6700
	EmptyBuffer                 LedgerError = 0x6982
	OutputBufferTooSmall        LedgerError = 0x6983
	DataIsInvalid               LedgerError = 0x6a80
	ConditionsNotSatisfied      LedgerError = 0x6985
	TransactionRejected         LedgerError = 0x6986
	BadKeyHandle                LedgerError = 0x6a81
	InvalidP1P2                 LedgerError = 0x6b00
	InstructionNotSupported     LedgerError = 0x6d00
	AppDoesNotSeemToBeOpen      LedgerError = 0x6e01
	UnknownError                LedgerError = 0x6f00
	SignVerifyError             LedgerError = 0x6f01
)

// LedgerAvalanche represents a connection to the Avax app in a Ledger device
type LedgerAvalanche struct {
	api     ledger_go.LedgerDevice
	version VersionInfo
}

// VersionInfo contains app version information
type VersionInfo struct {
	AppMode uint8
	Major   uint8
	Minor   uint8
	Patch   uint8
}

func (c VersionInfo) String() string {
	return fmt.Sprintf("%d.%d.%d", c.Major, c.Minor, c.Patch)
}

type VersionRequiredError struct {
	Found    VersionInfo
	Required VersionInfo
}

type ResponseSign struct {
	Hash      []byte
	Signature map[string][]byte
}

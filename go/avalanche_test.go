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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ledger Test Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young

func Test_UserFindLedger(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf(err.Error())
	}

	assert.NotNil(t, userApp)
	defer userApp.Close()
}

func Test_UserGetVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	version, err := userApp.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println(version)

	assert.Equal(t, uint8(0x0), version.AppMode, "TESTING MODE ENABLED!!")
	assert.Equal(t, uint8(0x0), version.Major, "Wrong Major version")
	assert.Equal(t, uint8(0x6), version.Minor, "Wrong Minor version")
	assert.Equal(t, uint8(0x5), version.Patch, "Wrong Patch version")
}

func Test_UserGetPublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	path := "m/44'/9000'/0'/0/0"
	hrp := ""
	chainID := ""
	showAddress := false

	publicKey, hash, err := userApp.GetPubKey(path, showAddress, hrp, chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(publicKey),
		"Public key has wrong length: %x, expected length: %x\n", publicKey, 66)
	fmt.Printf("PUBLIC KEY: %x\n", publicKey)

	assert.Equal(t, 20, len(hash),
		"Public key has wrong length: %x, expected length: %x\n", hash, 40)
	fmt.Printf("HASH: %x\n", hash)

	assert.Equal(t,
		"03cb5a33c61595206294140c45efa8a817533e31aa05ea18343033a0732a677005",
		hex.EncodeToString(publicKey),
		"Unexpected publicKey")

	assert.Equal(t,
		"62bcd95fccdfa668eb12be771a557d3595950799",
		hex.EncodeToString(hash),
		"Unexpected hash")
}

func Test_UserGetPublicKeyETH(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	pathETH := "m/44'/60'/0'/0'/5"
	hrp := ""
	chainID := ""
	showAddress := false

	publicKey, hash, err := userApp.GetPubKey(pathETH, showAddress, hrp, chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(publicKey),
		"Public key has wrong length: %x, expected length: %x\n", publicKey, 66)
	fmt.Printf("PUBLIC KEY: %x\n", publicKey)

	assert.Equal(t, 20, len(hash),
		"Public key has wrong length: %x, expected length: %x\n", hash, 40)
	fmt.Printf("HASH: %x\n", hash)

	assert.Equal(t,
		"03cb5a33c61595206294140c45efa8a817533e31aa05ea18343033a0732a677005",
		hex.EncodeToString(publicKey),
		"Unexpected publicKey")

	assert.Equal(t,
		"62bcd95fccdfa668eb12be771a557d3595950799",
		hex.EncodeToString(hash),
		"Unexpected hash")
}

func Test_UserPK_HDPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	hrp := ""
	chainID := ""
	showAddress := false

	expected := []string{
		"034fef9cd7c4c63588d3b03feb5281b9d232cba34d6f3d71aee59211ffbfe1fe87",
		"0260d0487a3dfce9228eee2d0d83a40f6131f551526c8e52066fe7fe1e4a509666",
		"03a2670393d02b162d0ed06a08041e80d86be36c0564335254df7462447eb69ab3",
		"033222fc61795077791665544a90740e8ead638a391a3b8f9261f4a226b396c042",
		"03f577473348d7b01e7af2f245e36b98d181bc935ec8b552cde5932b646dc7be04",
		"0222b1a5486be0a2d5f3c5866be46e05d1bde8cda5ea1c4c77a9bc48d2fa2753bc",
		"0377a1c826d3a03ca4ee94fc4dea6bccb2bac5f2ac0419a128c29f8e88f1ff295a",
		"031b75c84453935ab76f8c8d0b6566c3fcc101cc5c59d7000bfc9101961e9308d9",
		"038905a42433b1d677cc8afd36861430b9a8529171b0616f733659f131c3f80221",
		"038be7f348902d8c20bc88d32294f4f3b819284548122229decd1adf1a7eb0848b",
	}

	for i := uint32(0); i < 10; i++ {
		path := fmt.Sprintf("m/44'/9000'/0'/0/%d", i)

		publicKey, hash, err := userApp.GetPubKey(path, showAddress, hrp, chainID)
		if err != nil {
			t.Fatalf("Detected error, err: %s\n", err.Error())
		}

		assert.Equal(
			t,
			33,
			len(publicKey),
			"Public key has wrong length: %x, expected length: %x\n", publicKey, 65)

		assert.Equal(
			t,
			expected[i],
			hex.EncodeToString(publicKey),
			"Public key 44'/118'/0'/0/%d does not match\n", i)

		assert.Equal(t, 20, len(hash),
			"Public key has wrong length: %x, expected length: %x\n", hash, 40)
		fmt.Printf("HASH: %x\n", hash)
	}
}

//func Test_UserSignMsg(t *testing.T) {
//	userApp, err := FindLedgerAvalancheApp()
//	if err != nil {
//		t.Fatalf(err.Error())
//	}
//	defer userApp.Close()
//
//	message := "Welcome to OpenSea!\n\nClick to sign in and accept the OpenSea Terms of Service: https://opensea.io/tos\n\nThis request will not trigger a blockchain transaction or cost any gas fees.\n\nYour authentication status will reset after 24 hours.\n\nWallet address:\n0x9858effd232b4033e47d90003d41ec34ecaeda94\n\nNonce:\n2b02c8a0-f74f-4554-9821-a28054dc9121"
//}

func Test_UserSign(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	rootPath := "m/44'/9000'/0'"
	signers := []string{"0/0", "5/8"}

	simpleTransferData := []byte{
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x05,
		0xab, 0x68, 0xeb, 0x1e, 0xe1, 0x42, 0xa0, 0x5c,
		0xfe, 0x76, 0x8c, 0x36, 0xe1, 0x1f, 0x0b, 0x59,
		0x6d, 0xb5, 0xa3, 0xc6, 0xc7, 0x7a, 0xab, 0xe6,
		0x65, 0xda, 0xd9, 0xe6, 0x38, 0xca, 0x94, 0xf7,
		0x00, 0x00, 0x00, 0x02,
		0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
		0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
		0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
		0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa,
		0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x7F, 0x67, 0x1C, 0x73, 0x0D, 0x48, 0x07, 0xC2,
		0x9E, 0xA1, 0x9B, 0x19, 0xA2, 0x3C, 0x70, 0x0B,
		0x19, 0x8F, 0x8B, 0x51,
		0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
		0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
		0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
		0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa,
		0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x6A, 0xCB, 0xD8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		// output to be filtered for path 0/100
		3, 85, 118, 137, 182, 146, 213, 18, 105, 110, 165, 183, 74, 230, 225, 34, 62, 126, 4, 138, // 20-byte address
		0x00, 0x00, 0x00, 0x02,
		0x1C, 0x03, 0x06, 0xE5, 0x8B, 0x75, 0x4E, 0xEB,
		0x92, 0xE7, 0xA5, 0x79, 0xC5, 0x9A, 0x69, 0x33,
		0x23, 0xCD, 0x99, 0x94, 0xA5, 0x94, 0x61, 0x62,
		0x72, 0x6F, 0x3B, 0x68, 0x0E, 0x9E, 0x48, 0x34,
		0x00, 0x00, 0x00, 0x00,
		0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
		0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
		0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
		0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa,
		0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x29, 0x71, 0x0D, 0xE0, 0x93, 0xE2, 0xF4, 0x10,
		0xB5, 0xA3, 0x5E, 0x2C, 0x60, 0x59, 0x38, 0x39,
		0x2D, 0xA0, 0xDE, 0x80, 0x2C, 0x74, 0xE2, 0x5D,
		0x78, 0xD2, 0xBF, 0x11, 0x87, 0xDC, 0x9A, 0xD6,
		0x00, 0x00, 0x00, 0x00, 0x3d, 0x9b, 0xda, 0xc0, 0xed, 0x1d, 0x76, 0x13,
		0x30, 0xcf, 0x68, 0x0e, 0xfd, 0xeb, 0x1a, 0x42,
		0x15, 0x9e, 0xb3, 0x87, 0xd6, 0xd2, 0x95, 0x0c,
		0x96, 0xf7, 0xd2, 0x8f, 0x61, 0xbb, 0xe2, 0xaa,
		0x00, 0x00, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x7A, 0x11, 0x9C, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00}

	response, err := userApp.Sign(rootPath, signers, simpleTransferData, nil)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	if len(response.Signature) > 10000 {
		return
	}

	hrp := ""
	chainID := ""
	h := sha256.New()
	h.Write([]byte(simpleTransferData))
	msgHash := h.Sum(nil)

	err = userApp.VerifyMultipleSignatures(*response, msgHash, rootPath, signers, hrp, chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}
}

func Test_UserSignHash(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode.")
	}
	userApp, err := FindLedgerAvalancheApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	rootPath := "m/44'/9000'/0'"
	signingList := []string{"0/0", "4/8"}

	message := "AvalancheApp"
	h := sha256.New()
	h.Write([]byte(message))
	hash := h.Sum(nil)

	response, err := userApp.SignHash(rootPath, signingList, hash)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	hrp := ""
	chainID := ""
	err = userApp.VerifyMultipleSignatures(*response, hash, rootPath, signingList, hrp, chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}
}

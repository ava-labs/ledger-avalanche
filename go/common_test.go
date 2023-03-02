/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_PrintVersion(t *testing.T) {
	reqVersion := VersionInfo{0, 1, 2, 3}
	s := fmt.Sprintf("%v", reqVersion)
	assert.Equal(t, "1.2.3", s)
}

func Test_SerializePath(t *testing.T) {
	path := "m/44'/9000'/0'/0/0"
	expectedSerializedPath := []byte{0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x23, 0x28, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	serializedPath, err := SerializePath(path)

	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}
	assert.Equal(t, expectedSerializedPath, serializedPath)
}

func Test_SerializePathSuffix(t *testing.T) {
	suffixList := []string{"0/0", "4/8", "5/8"}
	serSuffix0 := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	serSuffix1 := []byte{0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08}
	serSuffix2 := []byte{0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08}
	expectedSerializedSuffixList := [3][]byte{serSuffix0, serSuffix1, serSuffix2}

	if len(suffixList) != len(expectedSerializedSuffixList) {
		t.Fatalf("Sizes don't match\n")
	}

	for idx, suffix := range suffixList {
		serializedSuffix, err := SerializePathSuffix(suffix)
		if err != nil {
			t.Fatalf("Detected error, err: %s\n", err.Error())
		}
		assert.Equal(t, expectedSerializedSuffixList[idx], serializedSuffix)
	}
}

func Test_SerializeChainID(t *testing.T) {
	chainID := "3qbR1eZRqXUWroWKKYhbDmR3FfqTHfqSU8zZSxtANzYh"
	expectedSerializedChainID := []byte{0x20, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a}
	serializedChainID, err := SerializeChainID(chainID)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}
	assert.Equal(t, expectedSerializedChainID, serializedChainID)
}

func Test_SerializeHrp(t *testing.T) {
	hrp := "zemu"
	expectedSerializedHrp := []byte{0x04, 0x7a, 0x65, 0x6d, 0x75}
	serializedHrp, err := SerializeHrp(hrp)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}
	assert.Equal(t, expectedSerializedHrp, serializedHrp)
}

func Test_RemoveDuplicates(t *testing.T) {
	duplicatedList := []string{"element0", "element1", "element0", "element2", "element3", "element4", "element5", "element3"}
	expectedList := []string{"element0", "element1", "element2", "element3", "element4", "element5"}

	cleanedList := RemoveDuplicates(duplicatedList)

	assert.Equal(t, expectedList, cleanedList)
}

func Test_ConcatMessageAndChangePath(t *testing.T) {

}

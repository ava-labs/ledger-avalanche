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
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mr-tron/base58"
)

func (e VersionRequiredError) Error() string {
	//return fmt.Sprintf("App Version required %s - Version found: %s", e.Required, e.Found)
	return fmt.Sprintf("App Version required %s - Version found: %s", "asd", "123")
}

// CheckVersion compares the current version with the required version
func CheckVersion(ver VersionInfo, req VersionInfo) error {
	if ver.Major != req.Major {
		if ver.Major > req.Major {
			return nil
		}
		return NewVersionRequiredError(req, ver)
	}

	if ver.Minor != req.Minor {
		if ver.Minor > req.Minor {
			return nil
		}
		return NewVersionRequiredError(req, ver)
	}

	if ver.Patch >= req.Patch {
		return nil
	}
	return NewVersionRequiredError(req, ver)
}

func NewVersionRequiredError(req VersionInfo, ver VersionInfo) error {
	return &VersionRequiredError{
		Found:    ver,
		Required: req,
	}
}

func SerializePath(path string) ([]byte, error) {
	if !strings.HasPrefix(path, "m") {
		return nil, errors.New(`Path should start with "m" (e.g "m/44\'/5757\'/5\'/0/3")`)
	}

	pathArray := strings.Split(path, "/")

	if len(pathArray) != 6 && len(pathArray) != 5 && len(pathArray) != 4 {
		return nil, errors.New("Invalid path. (e.g \"m/44'/5757'/5'/0/3\")")
	}

	buf := make([]byte, 1+(len(pathArray)-1)*4)
	buf[0] = byte(len(pathArray) - 1) // first byte is the path length

	for i := 1; i < len(pathArray); i++ {
		var value uint32
		child := pathArray[i]
		if strings.HasSuffix(child, "'") {
			value += HARDENED
			child = child[:len(child)-1]
		}

		childNumber, err := strconv.ParseUint(child, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("Invalid path : %s is not a number. (e.g \"m/44'/461'/5'/0/3\")", child)
		}

		if childNumber >= HARDENED {
			return nil, errors.New("Incorrect child value (bigger or equal to 0x80000000)")
		}

		value += uint32(childNumber)

		binary.BigEndian.PutUint32(buf[1+4*(i-1):1+4*i], value)
	}

	return buf, nil
}

func SerializePathSuffix(path string) ([]byte, error) {
	if strings.HasPrefix(path, "m") {
		return nil, errors.New(`Path suffix do not start with "m" (e.g "0/3")`)
	}

	pathArray := strings.Split(path, "/")
	if len(pathArray) != 2 {
		return nil, errors.New(`Invalid path suffix. (e.g "0/3")`)
	}

	buf := make([]byte, 1+len(pathArray)*4)
	buf[0] = byte(len(pathArray))

	for i, child := range pathArray {
		value := 0
		if strings.HasSuffix(child, "'") {
			return nil, errors.New(`Invalid hardened path suffix. (e.g "0/3")`)
		}
		childNumber, err := strconv.Atoi(child)
		if err != nil {
			return nil, errors.New(`Invalid path: ` + child + ` is not a number. (e.g "0/3")`)
		}
		if childNumber >= HARDENED {
			return nil, errors.New(`Incorrect child value (bigger or equal to 0x80000000)`)
		}
		value += childNumber

		buf[1+4*i] = byte(value >> 24)
		buf[2+4*i] = byte(value >> 16)
		buf[3+4*i] = byte(value >> 8)
		buf[4+4*i] = byte(value)
	}

	return buf, nil
}

// SerializeChainID serializes a chain ID into a byte slice
func SerializeChainID(chainID string) ([]byte, error) {
	if chainID == "" {
		return []byte{0}, nil
	}

	decoded, err := base58.Decode(chainID)
	if err != nil {
		return nil, err
	}

	if len(decoded) == 36 {
		// chop checksum off
		decoded = decoded[:32]
	} else if len(decoded) != 32 {
		return nil, errors.New("ChainID was not 32 bytes long (encoded with base58)")
	}

	return append([]byte{byte(len(decoded))}, decoded...), nil
}

// SerializeHrp serializes an HRP into a byte slice
func SerializeHrp(hrp string) ([]byte, error) {
	if hrp == "" {
		return []byte{0}, nil
	}

	bufHrp := make([]byte, 0, len(hrp))
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return nil, errors.New("all characters in the HRP must be in the [33, 126] range")
		}
		bufHrp = append(bufHrp, byte(c))
	}

	return append([]byte{byte(len(bufHrp))}, bufHrp...), nil
}

func RemoveDuplicates(elements []string) []string {
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			result = append(result, elements[v])
		}
	}
	return result
}

func ConcatMessageAndChangePath(message []byte, path []string) []byte {
	msg := append([]byte{}, message...)
	if path == nil {
		return append([]byte{0}, msg...)
	}
	buffer := []byte{byte(len(path))}
	for _, element := range path {
		pathBuf, err := SerializePathSuffix(element)
		if err != nil {
			return nil
		}
		buffer = append(buffer, pathBuf...)
	}
	return append(buffer, msg...)
}

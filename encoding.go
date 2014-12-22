/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"strings"
)

var stripWhitespaceRegex = regexp.MustCompile("\\s")

// Buffers that know how to do base64 and bigint.
type JsonBuffer json.RawMessage

func (buf JsonBuffer) MarshalJSON() ([]byte, error) {
	str := base64URLEncode(buf)
	return json.Marshal(str)
}

func (buf *JsonBuffer) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	if str == "" {
		return nil
	}

	*buf, err = base64URLDecode(str)
	return err
}

func (buf JsonBuffer) ToBigInt() *big.Int {
	ret := big.NewInt(0)
	ret.SetBytes(buf)
	return ret
}

func (buf JsonBuffer) ToInt() int {
	return int(buf.ToBigInt().Int64())
}

// Url-safe base64 encode that strips padding
func base64URLEncode(data []byte) string {
	var result = base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(result, "=")
}

// Url-safe base64 decoder that adds padding
func base64URLDecode(data interface{}) ([]byte, error) {
	if data, ok := data.(string); ok {
		var missing = (4 - len(data)%4) % 4
		data += strings.Repeat("=", missing)
		return base64.URLEncoding.DecodeString(data)
	}

	return nil, errors.New("square/go-jose: invalid input data")
}

// Helper function to serialize known-good objects
func serializeJSONChecked(value interface{}) []byte {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return out
}

// Strip all newlines and whitespace
func stripWhitespace(data string) string {
	return stripWhitespaceRegex.ReplaceAllString(data, "")
}

// Perform compression based on algorithm
func compress(algorithm CompressionAlgorithm, input []byte) ([]byte, error) {
	switch algorithm {
	case DEFLATE:
		return deflate(input)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// Perform decompression based on algorithm
func decompress(algorithm CompressionAlgorithm, input []byte) ([]byte, error) {
	switch algorithm {
	case DEFLATE:
		return inflate(input)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// Compress with DEFLATE
func deflate(input []byte) ([]byte, error) {
	output := new(bytes.Buffer)
	writer, err := flate.NewWriter(output, 1)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(writer, bytes.NewBuffer(input))
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	return output.Bytes(), err
}

// Decompress with DEFLATE
func inflate(input []byte) ([]byte, error) {
	output := new(bytes.Buffer)
	reader := flate.NewReader(bytes.NewBuffer(input))

	_, err := io.Copy(output, reader)
	if err != nil {
		return nil, err
	}

	err = reader.Close()
	return output.Bytes(), err
}

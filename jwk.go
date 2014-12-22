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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
)

// rawJsonWebKey represents a raw JWK JSON object. Used for parsing/serializing.
type rawJsonWebKey struct {
	Kty    string     `json:"kty,omitempty"`
	Use    string     `json:"use,omitempty"`
	KeyOps string     `json:"key_ops,omitempty"`
	Alg    string     `json:"alg,omitempty"`
	Kid    string     `json:"kid,omitempty"`
	X5u    string     `json:"x5u,omitempty"`
	X5c    string     `json:"x5c,omitempty"`
	X5t    string     `json:"x5t,omitempty"`
	X5t256 string     `json:"x5t#S256,omitempty"`
	N      JsonBuffer `json:"n,omitempty"`
	E      JsonBuffer `json:"e,omitempty"`
	Crv    string     `json:"crv,omitempty"`
	X      JsonBuffer `json:"x,omitempty"`
	Y      JsonBuffer `json:"y,omitempty"`
	D      JsonBuffer `json:"d,omitempty"`
	P      JsonBuffer `json:"p,omitempty"`
	Q      JsonBuffer `json:"q,omitempty"`
	DP     JsonBuffer `json:"dp,omitempty"`
	DQ     JsonBuffer `json:"dq,omitempty"`
	QI     JsonBuffer `json:"qi,omitempty"`
}

type JsonWebKey struct {
	KeyType    JoseKeyType
	PublicKey  crypto.PublicKey
	PrivateKey crypto.PrivateKey
}

// UnmarshalJSON reads a Json Web Key from it's serialized representation.
func (jwk *JsonWebKey) UnmarshalJSON(data []byte) (err error) {
	var raw rawJsonWebKey
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	switch JoseKeyType(raw.Kty) {
	case KeyTypeEC:
		err = jwk.unmarshalEC(raw)
	case KeyTypeRSA:
	default:
		err = fmt.Errorf("square/go-jose: unknown key type '%s'", raw.Kty)
	}

	return
}

func (jwk *JsonWebKey) unmarshalRSA(raw rawJsonWebKey) error {
	if raw.N == nil || raw.E == nil {
		return fmt.Errorf("square/go-jose: missing n/e values in RSA public key")
	}

	var pub *rsa.PublicKey
	var priv *rsa.PrivateKey

	pub = &rsa.PublicKey{
		N: raw.N.ToBigInt(),
		E: raw.E.ToInt(),
	}

	if raw.D != nil && raw.P != nil && raw.Q != nil {
		var precomp rsa.PrecomputedValues
		if raw.DP != nil && raw.DQ != nil && raw.QI != nil {
			precomp = rsa.PrecomputedValues{
				Dp:   raw.DP.ToBigInt(),
				Dq:   raw.DQ.ToBigInt(),
				Qinv: raw.QI.ToBigInt(),
			}
		}

		priv = &rsa.PrivateKey{
			PublicKey: *pub,
			D:         raw.D.ToBigInt(),
			Primes: []*big.Int{
				raw.P.ToBigInt(),
				raw.Q.ToBigInt(),
			},
			Precomputed: precomp,
		}
	}

	return nil
}

func (jwk *JsonWebKey) unmarshalEC(raw rawJsonWebKey) error {
	var curve elliptic.Curve
	switch raw.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return fmt.Errorf("square/go-jose: unknown elliptic curve '%s'", raw.Crv)
	}

	if raw.X == nil || raw.Y == nil {
		return fmt.Errorf("square/go-jose: missing x/y values in EC public key")
	}

	var pub *ecdsa.PublicKey
	var priv *ecdsa.PrivateKey

	pub = &ecdsa.PublicKey{
		Curve: curve,
		X:     raw.X.ToBigInt(),
		Y:     raw.Y.ToBigInt(),
	}

	if raw.D != nil {
		priv = &ecdsa.PrivateKey{
			PublicKey: *pub,
			D:         raw.D.ToBigInt(),
		}
	}

	jwk.PublicKey = pub
	jwk.PrivateKey = priv

	return nil
}

// MarshalJSON serializes a Json Web Key.
func (jwk JsonWebKey) MarshalJSON() ([]byte, error) {
	return nil, nil
}

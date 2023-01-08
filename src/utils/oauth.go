package utils

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
)

func GetPublicKey(issuerUri string, kid string) (rsa.PublicKey, error) {
	jwksUri, err := getJwksUri(issuerUri)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	keys, err := getJwks(jwksUri)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	key, err := getKey(keys, kid)
	if err != nil {
		return key, err
	}

	return key, nil
}

func getJwksUri(issuerUri string) (string, error) {
	// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	resp, err := http.Get(issuerUri + "/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var openIdConfig map[string]any
	json.Unmarshal(body, &openIdConfig)

	return openIdConfig["jwks_uri"].(string), nil
}

type JwksKey struct {
	Kty string
	Kid string
	Use string
	Alg string
	N   string
	E   string
}

func getJwks(jwksUri string) ([]JwksKey, error) {
	// https://www.rfc-editor.org/rfc/rfc7517#section-5
	resp, err := http.Get(jwksUri + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}

	// Read the body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	type JwksResponse struct {
		Keys []JwksKey
	}

	// JSON Object -> array of JwksKey
	var data JwksResponse
	json.Unmarshal(body, &data)
	key_array := data.Keys

	return key_array, nil
}

func getKey(keys []JwksKey, kid string) (rsa.PublicKey, error) {
	for _, key := range keys {
		if key.Kid == kid {
			// Extract N and format it
			N := big.Int{}
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return rsa.PublicKey{}, err
			}
			N.SetBytes(nBytes)

			// Extrace E and format it
			E := big.Int{}
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return rsa.PublicKey{}, err
			}
			E.SetBytes(eBytes)
			e := int(E.Int64())

			// Build the public key object
			return rsa.PublicKey{
				N: &N,
				E: e,
			}, nil
		}
	}
	return rsa.PublicKey{}, errors.New("No matching key found")
}

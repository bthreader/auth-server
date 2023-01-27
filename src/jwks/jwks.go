package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
)

// Returns the public key with the id `kid` using the issuers OpenID
// configuration
func GetIssuerPublicKey(issuerUri string, kid string) (rsa.PublicKey, error) {
	jwksUri, err := getJwksUri(issuerUri)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	keys, err := GetJwks(jwksUri)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	key, err := GetKeyFromJwks(keys, kid)
	if err != nil {
		return key, err
	}

	return key, nil
}

// From the provider config page (as specified by OpenID) gets the JWKS URI
func getJwksUri(issuerUri string) (string, error) {
	resp, err := http.Get(issuerUri + "/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var body map[string]any
	err = json.Unmarshal(bodyBytes, &body)
	if err != nil {
		return "", err
	}

	return body["jwks_uri"].(string), nil
}

// From the JWKS URI gets all the keys and serializes them for processing
func GetJwks(jwksUri string) ([]JwksKey, error) {
	resp, err := http.Get(jwksUri)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data JwksResponse
	json.Unmarshal(body, &data)
	key_array := data.Keys

	return key_array, nil
}

// From the array of keys matches the key with the key id (`kid`).
// Returns "No matching key found" error if one doesn't exist.
func GetKeyFromJwks(keys []JwksKey, kid string) (rsa.PublicKey, error) {
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

			return rsa.PublicKey{
				N: &N,
				E: e,
			}, nil
		}
	}
	return rsa.PublicKey{}, errors.New("No matching key found")
}

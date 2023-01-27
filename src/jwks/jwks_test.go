package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"reflect"
	"testing"
)

const APPLE_JWKS_URI string = "https://appleid.apple.com/auth/keys"
const APPLE_ISSUER_URI string = "https://appleid.apple.com"

func TestGetJwksUris(t *testing.T) {
	uri, err := getJwksUri(APPLE_ISSUER_URI)
	if err != nil {
		t.FailNow()
	}
	if uri != APPLE_JWKS_URI {
		t.FailNow()
	}
}

func TestGetAppleJwks(t *testing.T) {
	keys, err := GetJwks(APPLE_JWKS_URI)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	if keys[0].Kty != "RSA" {
		t.Fail()
	}
	if keys[0].Use != "sig" {
		t.Fail()
	}
	if keys[0].Alg != "RS256" {
		t.Fail()
	}
}

func TestGetKeyFromJwks(t *testing.T) {
	n := "or83anRxFNTbjOy47m4SRDZQ7WpX_yjJdqN_LgNUBfbb_VnBwIUv_k4E1tXOE1yQC704YAT6JQ4AJtvLw598NxSuyXSvo-JCQ4pNugjVZ0w2MErJtARcxCu4LI6gsA_xSfSfuNVVSdrHqg8G-wsog0BS6N4M5IJtUlRR6UtjLaJxgqFGzV5sHWAfmpBekqCC5l19OXtE9J00r_Wjo4kfleonpVlEHszx5KUzShfGTGwgoeryNcp4yBULh8El8vt50a4SP_D74gCL5YINUl4E8hfQoqbPoxLj33oXYEvMKL34xYErEF5Tw39oAEfky3OgTXsCQvAp5il7HQjRY1JGow"
	e := "AQAB"

	keySet := []JwksKey{{
		Kty: "irrelevant",
		Kid: "match",
		Use: "irrelevant",
		Alg: "irrelevant",
		N:   n,
		E:   e,
	}}

	// Format n
	nFormatted := big.Int{}
	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	nFormatted.SetBytes(nBytes)

	// Format e
	eFormatted := big.Int{}
	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	eFormatted.SetBytes(eBytes)
	eInt := int(eFormatted.Int64())

	matchedKey, err := GetKeyFromJwks(keySet, "match")
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	expectedKey := rsa.PublicKey{
		N: &nFormatted,
		E: eInt,
	}

	if !reflect.DeepEqual(expectedKey, matchedKey) {
		t.FailNow()
	}
}

func TestGetPublicKeyFail(t *testing.T) {
	_, err := GetIssuerPublicKey(APPLE_ISSUER_URI, "spaghettibolognese")
	if err == nil {
		t.FailNow()
	}
}

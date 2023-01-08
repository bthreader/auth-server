package utils

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

const APPLE_JWKS_URI string = "https://appleid.apple.com/auth/keys"
const APPLE_ISSUER_URI string = "https://appleid.apple.com"

func TestGetJwksUris(t *testing.T) {
	res, err := getJwksUri(APPLE_ISSUER_URI)
	if err != nil {
		t.FailNow()
	}
	if res != APPLE_JWKS_URI {
		t.FailNow()
	}
}

func TestGetAppleJwks(t *testing.T) {
	res, err := getJwks(APPLE_JWKS_URI)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	if res[0].Kty != "RSA" {
		t.Fail()
	}
	if res[0].Use != "sig" {
		t.Fail()
	}
	if res[0].Alg != "RS256" {
		t.Fail()
	}
}

func TestGetKey(t *testing.T) {
	n := "2Zc5d0-zkZ5AKmtYTvxHc3vRc41YfbklflxG9SWsg5qXUxvfgpktGAcxXLFAd9Uglzow9ezvmTGce5d3DhAYKwHAEPT9hbaMDj7DfmEwuNO8UahfnBkBXsCoUaL3QITF5_DAPsZroTqs7tkQQZ7qPkQXCSu2aosgOJmaoKQgwcOdjD0D49ne2B_dkxBcNCcJT9pTSWJ8NfGycjWAQsvC8CGstH8oKwhC5raDcc2IGXMOQC7Qr75d6J5Q24CePHj_JD7zjbwYy9KNH8wyr829eO_G4OEUW50FAN6HKtvjhJIguMl_1BLZ93z2KJyxExiNTZBUBQbbgCNBfzTv7JrxMw"
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
	fmt.Println(nFormatted.String())

	// Format e
	eFormatted := big.Int{}
	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	eFormatted.SetBytes(eBytes)
	eInt := int(eFormatted.Int64())
	fmt.Println(eInt)

	matchedKey, err := getKey(keySet, "match")
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

func TestGetPublicKey(t *testing.T) {
	_, err := GetPublicKey(APPLE_ISSUER_URI, "spaghettibolognese")
	if err == nil {
		t.FailNow()
	}
}

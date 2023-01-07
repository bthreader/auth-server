package utils

import (
	"reflect"
	"testing"
)

func TestGetJwks(t *testing.T) {
	// Example input from Apple
	res, err := getJwks("https://appleid.apple.com/auth/keys")
	if err != nil {
		t.FailNow()
	}
	if !reflect.DeepEqual(res[0].Kty, "RSA") {
		t.FailNow()
	}
	if !reflect.DeepEqual(res[0].Use, "sig") {
		t.FailNow()
	}
	if !reflect.DeepEqual(res[0].Alg, "RS256") {
		t.FailNow()
	}
}

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

	var firstAppleKey = JwksKey{
		Kty: "RSA",
		Kid: "YuyXoY",
		Use: "sig",
		Alg: "RS256",
		N:   "1JiU4l3YCeT4o0gVmxGTEK1IXR-Ghdg5Bzka12tzmtdCxU00ChH66aV-4HRBjF1t95IsaeHeDFRgmF0lJbTDTqa6_VZo2hc0zTiUAsGLacN6slePvDcR1IMucQGtPP5tGhIbU-HKabsKOFdD4VQ5PCXifjpN9R-1qOR571BxCAl4u1kUUIePAAJcBcqGRFSI_I1j_jbN3gflK_8ZNmgnPrXA0kZXzj1I7ZHgekGbZoxmDrzYm2zmja1MsE5A_JX7itBYnlR41LOtvLRCNtw7K3EFlbfB6hkPL-Swk5XNGbWZdTROmaTNzJhV-lWT0gGm6V1qWAK2qOZoIDa_3Ud0Gw",
		E:   "AQAB",
	}

	if !reflect.DeepEqual(firstAppleKey, res[0]) {
		t.FailNow()
	}

}

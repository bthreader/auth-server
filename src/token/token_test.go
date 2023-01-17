package token

import "testing"

func TestGetPrivateKey(t *testing.T) {
	key, err := getPrivateKey()

	if err != nil {
		t.Log(err)
		t.FailNow()
	}
	if key == nil {
		t.Log("key is nil pointer")
		t.FailNow()
	}
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken(RefreshToken, "Jeff")

	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	// Add more tests here
	t.Log(token)
}

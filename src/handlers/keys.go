package handlers

import (
	"bthreader/auth-server/src/jwks"
	"bthreader/auth-server/src/token"
	"fmt"
	"strconv"

	"encoding/base64"
	"encoding/json"
	"net/http"
)

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	publicKey, err := token.GetPublicKey()
	if err != nil {
		fmt.Print(err)
		http.Error(w, "Cannot get public keys from server", http.StatusInternalServerError)
		return
	}

	jwk := jwks.JwksKey{
		Kty: "RSA",
		Kid: "0",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString([]byte(publicKey.N.String())),
		E:   base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(publicKey.E))),
	}

	keys := jwks.JwksResponse{
		Keys: append(make([]jwks.JwksKey, 0), jwk),
	}

	b, _ := json.Marshal(keys)

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

	return
}

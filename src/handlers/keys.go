package handlers

import (
	"bthreader/auth-server/src/oauth"
	"bthreader/auth-server/src/token"

	"encoding/json"
	"net/http"
)

func KeysHandler(w http.ResponseWriter, r *http.Request) {
	publicKey, err := token.GetPublicKey()
	if err != nil {
		http.Error(w, "Cannot get public keys from server", http.StatusInternalServerError)
	}

	jwk := oauth.JwksKey{
		Kty: "trigger",
		Kid: "0",
		Use: "hello",
		Alg: "RS256",
		N:   publicKey.N.String(),
		E:   "hello",
		// E:   string(publicKey.E),
	}

	keys := oauth.JwksResponse{
		Keys: append(make([]oauth.JwksKey, 0), jwk),
	}

	b, _ := json.Marshal(keys)

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

	return
}

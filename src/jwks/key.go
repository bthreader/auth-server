package jwks

// An entry in the "keys" JSON Array
// https://www.rfc-editor.org/rfc/rfc7517
type JwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

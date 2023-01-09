package oauth

// The response returned by a JWKS URI
type JwksResponse struct {
	Keys []JwksKey `json:"keys"`
}

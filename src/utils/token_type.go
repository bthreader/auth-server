package utils

type TokenType string

const (
	RefreshToken TokenType = "refresh"
	AccessToken  TokenType = "access"
)

package config

import "time"

const (
	// Keys
	UserIDKey       = "userID"
	UsernameKey     = "username"
	JWTTokenKey     = "accessToken"
	SecureFgp       = "secureFgp"
	RefreshTokenKey = "refreshToken"

	// Duration literals
	JWTMaxAgeMinutes         = 15
	RefreshTokenDurationDays = 30
)

var (
	// Time settings
	TimeZone = time.UTC

	// Duration variables
	JWTMaxAge            = time.Duration(JWTMaxAgeMinutes) * time.Minute
	RefreshTokenDuration = time.Duration(RefreshTokenDurationDays) * 24 * time.Hour
)

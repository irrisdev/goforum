package utils

import (
	"net/mail"
	"regexp"
	"strings"
)

// The following rules enforce input validation rules

// ValidateEmail performs basic validation of an email address
func ValidateEmail(email string) (bool, string) {
	// Trim spaces
	email = strings.TrimSpace(email)

	// Check if empty
	if email == "" {
		return false, "email is required"
	}

	// Check length
	if len(email) > 254 {
		return false, "email is too long"
	}

	// Use mail.ParseAddress for RFC-compliant validation
	_, err := mail.ParseAddress(email)
	if err != nil {
		return false, "invalid email format"
	}

	return true, ""
}

// ValidatePassword checks if a password meets security requirements
func ValidatePassword(password string) (bool, string) {
	// Check minimum length
	if len(password) < 8 {
		return false, "password must be at least 8 characters long"
	}

	// Check for at least one uppercase letter
	uppercase := regexp.MustCompile(`[A-Z]`)
	if !uppercase.MatchString(password) {
		return false, "password must contain at least one uppercase letter"
	}

	// Check for at least one lowercase letter
	lowercase := regexp.MustCompile(`[a-z]`)
	if !lowercase.MatchString(password) {
		return false, "password must contain at least one lowercase letter"
	}

	// Check for at least one digit
	digit := regexp.MustCompile(`[0-9]`)
	if !digit.MatchString(password) {
		return false, "password must contain at least one digit"
	}

	// Optionally check for special characters
	// special := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)
	// if !special.MatchString(password) {
	// 	return false, "password must contain at least one special character"
	// }

	return true, ""
}

// ValidateUsername checks if a username meets security requirements
func ValidateUsername(username string) (bool, string) {
	// Check minimum length
	if len(username) < 4 {
		return false, "username must be at least 4 characters long"
	}

	// Check maximum length (optional, but recommended)
	if len(username) > 20 {
		return false, "username cannot be longer than 20 characters"
	}

	// Check that username only contains letters and numbers
	alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !alphanumeric.MatchString(username) {
		return false, "username can only contain letters and numbers"
	}

	return true, ""
}

package cmd

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

// MyUser represents an ACME user for Let's Encrypt certificate generation.
// It implements the required interface for ACME protocol interactions including
// email registration, private key management, and certificate provisioning.
// Taken directly from the lego example, since we need very minimal support
// https://go-acme.github.io/lego/usage/library/
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

// NewMyUser creates a new ACME user with the given email and private key.
// The email is used for ACME registration and the private key for cryptographic operations.
// Returns a configured MyUser instance ready for certificate generation.
func NewMyUser(email string, key crypto.PrivateKey) *MyUser {
	return &MyUser{
		Email: email,
		key:   key,
	}
}

// GetEmail returns the user's email address for ACME registration.
// This method is required by the ACME user interface for account identification.
func (u *MyUser) GetEmail() string {
	return u.Email
}

// GetRegistration returns the user's ACME registration resource.
// Contains registration details and account information from the ACME server.
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}

// GetPrivateKey returns the user's private key for ACME operations.
// Used for signing ACME requests and certificate generation processes.
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

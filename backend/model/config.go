package model

import (
	"github.com/google/uuid"
	"time"
)

type Account struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	Name     *string `json:"name,omitempty"`
}

type ApiKey struct {
	Id      uuid.UUID `json:"id"`
	Comment string    `json:"comment"`
	Key     string    `json:"key"`
	Expires time.Time `json:"expires"`
}

type ConfigPreferences struct {
	Address             string `json:"address"`
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	AuthNocache         bool   `json:"authNocache"`
	VerifyX509Name      bool   `json:"verifyX509Name"`
}

type ApplicationConfig struct {
	Users         []Account         `json:"users"`
	ApiKeys       []ApiKey          `json:"apiKeys"`
	Preferences   ConfigPreferences `json:"preferences"`
	JwtSecretData string            `json:"jwtSecret"`
	JwtData       []byte
}

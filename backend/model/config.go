package model

type Account struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
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
	Preferences   ConfigPreferences `json:"preferences"`
	JwtSecretData string            `json:"jwtSecret"`
	JwtData       []byte
}

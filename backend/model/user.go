package model

type ConfigPublicAccount struct {
	Username string  `json:"username"`
	Name     *string `json:"name,omitempty"`
}

type ConfigPublicApiKey struct {
	Id      string `json:"id"`
	Comment string `json:"comment"`
	Expires string `json:"expires"`
}

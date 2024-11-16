package preference

import (
	b64 "encoding/base64"
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"rpiadm/backend/model"
	"rpiadm/backend/shell"
	"time"
)

type ConfigPublicPreferences struct {
	Address             string                      `json:"address"`
	DefaultAddress      string                      `json:"defaultAddress"`
	CertificateDuration int                         `json:"certificateDuration"`
	ExplicitExitNotify  bool                        `json:"explicitExitNotify"`
	AuthNoCache         bool                        `json:"authNoCache"`
	VerifyX509Name      bool                        `json:"verifyX509Name"`
	Users               []model.ConfigPublicAccount `json:"users"`
	ApiKeys             []model.ConfigPublicApiKey  `json:"apiKeys"`
	AllowAnonymousCsr   bool                        `json:"allowAnonymousCsr"`
}

type ApplicationConfig struct {
	Users         []model.Account         `json:"users"`
	ApiKeys       []model.ApiKey          `json:"apiKeys"`
	Preferences   model.ConfigPreferences `json:"preferences"`
	JwtSecretData string                  `json:"jwtSecret"`
	JwtData       []byte
}

func randomJwtSecret(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (pref *ApplicationConfig) LoadPreferences(ovpnConfigDir string) {
	pref.Users = make([]model.Account, 0)
	pref.ApiKeys = make([]model.ApiKey, 0)
	pref.Preferences.ExplicitExitNotify = true // default config value, will be overwritten by Unmarshal

	if _, err := os.Stat(ovpnConfigDir + "/config.json"); err == nil {
		log.Printf("Reading ovpn-admin config '%s'", ovpnConfigDir+"/config.json")
		rawJson := shell.ReadFile(ovpnConfigDir + "/config.json")
		err = json.Unmarshal([]byte(rawJson), pref)
		if err != nil {
			log.Fatal("Can't decode config {}", err)
			return
		}
	} else {
		log.Printf("Config file for ovpn-admin not found at '%s', using defaults", ovpnConfigDir+"/config.json")
	}

	if len(pref.JwtSecretData) == 0 {
		pref.JwtData = randomJwtSecret(64)
		pref.SavePreferences(ovpnConfigDir)
	} else {
		jwtData, err := b64.StdEncoding.DecodeString(pref.JwtSecretData)
		if err != nil {
			log.Printf("Cant decode jwtSecret %s", err)
			return
		}
		pref.JwtData = jwtData
	}
}

func (pref *ApplicationConfig) SavePreferences(ovpnConfigDir string) error {
	pref.JwtSecretData = b64.StdEncoding.EncodeToString(pref.JwtData)
	rawJson, err := json.MarshalIndent(pref, "", "  ")
	if err != nil {
		return err
	}
	return shell.WriteFile(ovpnConfigDir+"/config.json", rawJson)
}

func (config *ApplicationConfig) ExportPublicPreferences(defaultAddress string) *ConfigPublicPreferences {
	var preferences = new(ConfigPublicPreferences)
	preferences.Address = config.Preferences.Address
	preferences.DefaultAddress = defaultAddress
	preferences.CertificateDuration = 3600 * 24 * 365 * 10 // 10 years
	preferences.ExplicitExitNotify = config.Preferences.ExplicitExitNotify
	preferences.AuthNoCache = config.Preferences.AuthNocache
	preferences.VerifyX509Name = config.Preferences.VerifyX509Name
	preferences.ApiKeys = make([]model.ConfigPublicApiKey, 0)
	preferences.AllowAnonymousCsr = config.Preferences.AllowAnonymousCsr

	if config.Preferences.CertificateDuration > 0 {
		preferences.CertificateDuration = config.Preferences.CertificateDuration
	}

	for _, u := range config.Users {
		preferences.Users = append(preferences.Users, model.ConfigPublicAccount{Username: u.Username, Name: u.Name})
	}

	for _, u := range config.ApiKeys {
		preferences.ApiKeys = append(preferences.ApiKeys, ApiKeyMapper(u))
	}

	return preferences
}

func ApiKeyMapper(apiKey model.ApiKey) model.ConfigPublicApiKey {
	return model.ConfigPublicApiKey{Id: apiKey.Id.String(), Comment: apiKey.Comment, Expires: apiKey.Expires.Format(time.RFC3339)}
}

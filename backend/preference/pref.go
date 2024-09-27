package preference

import (
	b64 "encoding/base64"
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"rpiadm/backend/model"
	"rpiadm/backend/shell"
)

func randomJwtSecret(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func LoadPreferences(
	preference *model.ApplicationConfig,
	ovpnConfigDir string,
) {
	preference.Users = make([]model.Account, 0)
	preference.ApiKeys = make([]model.ApiKey, 0)
	preference.Preferences.ExplicitExitNotify = true // default config value, will be overwritten by Unmarshal

	if _, err := os.Stat(ovpnConfigDir + "/config.json"); err == nil {
		log.Printf("Reading ovpn-admin config '%s'", ovpnConfigDir+"/config.json")
		rawJson := shell.ReadFile(ovpnConfigDir + "/config.json")
		err = json.Unmarshal([]byte(rawJson), preference)
		if err != nil {
			log.Fatal("Can't decode config {}", err)
			return
		}
	} else {
		log.Printf("Config file for ovpn-admin not found at '%s', using defaults", ovpnConfigDir+"/config.json")
	}

	if len(preference.JwtSecretData) == 0 {
		preference.JwtData = randomJwtSecret(64)
		SavePreferences(ovpnConfigDir, preference)
	} else {
		jwtData, err := b64.StdEncoding.DecodeString(preference.JwtSecretData)
		if err != nil {
			log.Printf("Cant decode jwtSecret %s", err)
			return
		}
		preference.JwtData = jwtData
	}
}

func SavePreferences(ovpnConfigDir string, preference *model.ApplicationConfig) error {
	preference.JwtSecretData = b64.StdEncoding.EncodeToString(preference.JwtData)
	rawJson, err := json.MarshalIndent(preference, "", "  ")
	if err != nil {
		return err
	}
	return shell.WriteFile(ovpnConfigDir+"/config.json", rawJson)
}

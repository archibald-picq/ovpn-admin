package main

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type ConfigPublicPreferencesPost struct {
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	AuthNoCache         bool   `json:"authNoCache"`
	VerifyX509Name      string `json:"verifyX509Name"`
}

type ConfigPublicPreferences struct {
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	AuthNoCache         bool   `json:"authNoCache"`
	VerifyX509Name      string `json:"verifyX509Name"`
	Users               []ConfigPublicAccount `json:"users"`
}

type ConfigPublicAccount struct {
	Username         string `json:"username"`
	Name             string `json:"name"`
}

type Account struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	Name             string `json:"name"`
}

type ConfigPreferences struct {
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	AuthNocache         bool   `json:"authNocache"`
	Cipher              string `json:"cipher"`
	VerifyX509Name      string `json:"verifyX509Name"`
}

type ApplicationConfig struct {
	Users       []Account         `json:"users"`
	Preferences ConfigPreferences `json:"preferences"`
}

func loadConfig() ApplicationConfig {
	var config ApplicationConfig
	config.Preferences.ExplicitExitNotify = true // default config value, will be overwritten

	rawJson := fRead(*ovpnConfigFile)
	err := json.Unmarshal([]byte(rawJson), &config)
	if err != nil {
		log.Fatal("Can't read config")
		return config
	}
	return config
}

func (oAdmin *OvpnAdmin) saveConfigPreferences(w http.ResponseWriter, r *http.Request) {
	var post ConfigPublicPreferencesPost

	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		log.Errorln(err)
	}
	log.Printf("saving preferences %v", post)
	w.WriteHeader(http.StatusNoContent)
}


func (oAdmin *OvpnAdmin) savePreferencesFile() error {
	rawJson, err := json.MarshalIndent(oAdmin.applicationPreferences, "", "  ")
	if err != nil {
		return err
	}
	return fWriteBytes(*ovpnConfigFile, rawJson)
}

func (oAdmin *OvpnAdmin) exportPublicPreferences() *ConfigPublicPreferences {
	var preferences = new(ConfigPublicPreferences)
	preferences.CertificateDuration = 3600 * 24 * 365 * 10 // 10 years
	preferences.ExplicitExitNotify = oAdmin.applicationPreferences.Preferences.ExplicitExitNotify
	preferences.AuthNoCache = oAdmin.applicationPreferences.Preferences.AuthNocache
	preferences.VerifyX509Name = oAdmin.applicationPreferences.Preferences.VerifyX509Name

	if oAdmin.applicationPreferences.Preferences.CertificateDuration > 0 {
		preferences.CertificateDuration = oAdmin.applicationPreferences.Preferences.CertificateDuration
	}

	for _, u := range oAdmin.applicationPreferences.Users {
		preferences.Users = append(preferences.Users, ConfigPublicAccount{Username: u.Username, Name: u.Name})
	}

	return preferences
}

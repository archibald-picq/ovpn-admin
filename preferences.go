package main

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
)


type ConfigPublicPreferences struct {
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	Auth                string `json:"auth"`
	AuthNoCache         bool   `json:"authNoCache"`
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
	Auth                string `json:"auth"`
	AuthNocache         bool   `json:"authNocache"`
	Cipher              string `json:"cipher"`
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

func (oAdmin *OvpnAdmin) savePreferences() error {
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
	preferences.Auth = oAdmin.applicationPreferences.Preferences.Auth
	preferences.AuthNoCache = oAdmin.applicationPreferences.Preferences.AuthNocache

	if oAdmin.applicationPreferences.Preferences.CertificateDuration > 0 {
		preferences.CertificateDuration = oAdmin.applicationPreferences.Preferences.CertificateDuration
	}

	for _, u := range oAdmin.applicationPreferences.Users {
		preferences.Users = append(preferences.Users, ConfigPublicAccount{Username: u.Username, Name: u.Name})
	}

	return preferences
}

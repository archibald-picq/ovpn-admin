package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
)

type ConfigPublicPreferencesPost struct {
	Address             string `json:"address"`
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	AuthNoCache         bool   `json:"authNoCache"`
	VerifyX509Name      bool   `json:"verifyX509Name"`
}

type ConfigPublicPreferences struct {
	Address             string `json:"address"`
	DefaultAddress      string `json:"defaultAddress"`
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	AuthNoCache         bool   `json:"authNoCache"`
	VerifyX509Name      bool   `json:"verifyX509Name"`
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
	jwtData       []byte
}

func randomJwtSecret(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (app *OvpnAdmin) loadPreferences() {
	app.applicationPreferences.Users = make([]Account, 0)
	app.applicationPreferences.Preferences.ExplicitExitNotify = true // default config value, will be overwritten by Unmarshal

	if _, err := os.Stat(*ovpnConfigFile); err == nil {
		rawJson := fRead(*ovpnConfigFile)
		err = json.Unmarshal([]byte(rawJson), &app.applicationPreferences)
		if err != nil {
			log.Printf("Can't decode config")
			return
		}
	} else {
		log.Printf("No config file found, using defaults")
	}

	if len(*jwtSecretFile) > 0 {
		if _, err := os.Stat(*jwtSecretFile); err == nil {
			app.applicationPreferences.jwtData = []byte(fRead(*jwtSecretFile))
			app.savePreferences()
		}
	} else {
		if len(app.applicationPreferences.JwtSecretData) == 0 {
			app.applicationPreferences.jwtData = randomJwtSecret(64)
			app.savePreferences()
		} else {
			jwtData, err := b64.StdEncoding.DecodeString(app.applicationPreferences.JwtSecretData)
			if err != nil {
				log.Printf("Cant decode jwtSecret %s", err)
				return
			}
			app.applicationPreferences.jwtData = jwtData
		}
	}
}

func (app *OvpnAdmin) postPreferences(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var post ConfigPublicPreferencesPost
	log.Printf("saving preferences %v", r.Body)

	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		log.Printf("JSON.unmarshal error %v", err)
		jsonError, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Cant decode body: %s", err)})
		http.Error(w, string(jsonError), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("saving preferences %v", post)
	app.applicationPreferences.Preferences.Address = post.Address
	app.applicationPreferences.Preferences.ExplicitExitNotify = post.ExplicitExitNotify
	app.applicationPreferences.Preferences.CertificateDuration = post.CertificateDuration
	app.applicationPreferences.Preferences.AuthNocache = post.AuthNoCache
	app.applicationPreferences.Preferences.VerifyX509Name = post.VerifyX509Name
	app.savePreferences()
	w.WriteHeader(http.StatusNoContent)
}


func (app *OvpnAdmin) savePreferences() error {
	app.applicationPreferences.JwtSecretData = b64.StdEncoding.EncodeToString(app.applicationPreferences.jwtData)
	rawJson, err := json.MarshalIndent(app.applicationPreferences, "", "  ")
	if err != nil {
		return err
	}
	return fWriteBytes(*ovpnConfigFile, rawJson)
}

func (app *OvpnAdmin) exportPublicPreferences() *ConfigPublicPreferences {
	var preferences = new(ConfigPublicPreferences)
	preferences.Address = app.applicationPreferences.Preferences.Address
	preferences.DefaultAddress = fmt.Sprintf("%s:%d", app.outboundIp, app.serverConf.port)
	preferences.CertificateDuration = 3600 * 24 * 365 * 10 // 10 years
	preferences.ExplicitExitNotify = app.applicationPreferences.Preferences.ExplicitExitNotify
	preferences.AuthNoCache = app.applicationPreferences.Preferences.AuthNocache
	preferences.VerifyX509Name = app.applicationPreferences.Preferences.VerifyX509Name

	if app.applicationPreferences.Preferences.CertificateDuration > 0 {
		preferences.CertificateDuration = app.applicationPreferences.Preferences.CertificateDuration
	}

	for _, u := range app.applicationPreferences.Users {
		preferences.Users = append(preferences.Users, ConfigPublicAccount{Username: u.Username, Name: u.Name})
	}

	return preferences
}

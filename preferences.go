package main

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"net/http"
	b64 "encoding/base64"
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

func (oAdmin *OvpnAdmin) loadPreferences() {
	oAdmin.applicationPreferences.Users = make([]Account, 0)
	oAdmin.applicationPreferences.Preferences.ExplicitExitNotify = true // default config value, will be overwritten by Unmarshal

	if _, err := os.Stat(*ovpnConfigFile); err == nil {
		rawJson := fRead(*ovpnConfigFile)
		err = json.Unmarshal([]byte(rawJson), &oAdmin.applicationPreferences)
		if err != nil {
			log.Fatal("Can't decode config")
			return
		}
	} else {
		log.Infof("No config file found, using defaults")
	}

	if len(*jwtSecretFile) > 0 {
		if _, err := os.Stat(*jwtSecretFile); err == nil {
			oAdmin.applicationPreferences.jwtData = []byte(fRead(*jwtSecretFile))
			oAdmin.savePreferences()
		}
	} else {
		if len(oAdmin.applicationPreferences.JwtSecretData) == 0 {
			oAdmin.applicationPreferences.jwtData = randomJwtSecret(64)
			oAdmin.savePreferences()
		} else {
			jwtData, err := b64.StdEncoding.DecodeString(oAdmin.applicationPreferences.JwtSecretData)
			if err != nil {
				log.Warnf("Cant decode jwtSecret %s", err)
				return
			}
			oAdmin.applicationPreferences.jwtData = jwtData
		}
	}
}

func (oAdmin *OvpnAdmin) postPreferences(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	auth := getAuthCookie(r)
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var post ConfigPublicPreferencesPost
	log.Printf("saving preferences %v", r.Body)

	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		log.Errorln(err)
		jsonError, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Cant decode body: %s", err)})
		http.Error(w, string(jsonError), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("saving preferences %v", post)
	oAdmin.applicationPreferences.Preferences.Address = post.Address
	oAdmin.applicationPreferences.Preferences.ExplicitExitNotify = post.ExplicitExitNotify
	oAdmin.applicationPreferences.Preferences.CertificateDuration = post.CertificateDuration
	oAdmin.applicationPreferences.Preferences.AuthNocache = post.AuthNoCache
	oAdmin.applicationPreferences.Preferences.VerifyX509Name = post.VerifyX509Name
	oAdmin.savePreferences()
	w.WriteHeader(http.StatusNoContent)
}


func (oAdmin *OvpnAdmin) savePreferences() error {
	oAdmin.applicationPreferences.JwtSecretData = b64.StdEncoding.EncodeToString(oAdmin.applicationPreferences.jwtData)
	rawJson, err := json.MarshalIndent(oAdmin.applicationPreferences, "", "  ")
	if err != nil {
		return err
	}
	return fWriteBytes(*ovpnConfigFile, rawJson)
}

func (oAdmin *OvpnAdmin) exportPublicPreferences() *ConfigPublicPreferences {
	var preferences = new(ConfigPublicPreferences)
	preferences.Address = oAdmin.applicationPreferences.Preferences.Address
	preferences.DefaultAddress = fmt.Sprintf("%s:%d", oAdmin.outboundIp, oAdmin.serverConf.port)
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

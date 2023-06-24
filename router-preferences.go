package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/preference"
)

type ConfigPublicPreferencesPost struct {
	Address             string `json:"address"`
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	AuthNoCache         bool   `json:"authNoCache"`
	VerifyX509Name      bool   `json:"verifyX509Name"`
}

func (app *OvpnAdmin) postPreferences(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
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
	preferences := &app.applicationPreferences
	preferences.Preferences.Address = post.Address
	preferences.Preferences.ExplicitExitNotify = post.ExplicitExitNotify
	preferences.Preferences.CertificateDuration = post.CertificateDuration
	preferences.Preferences.AuthNocache = post.AuthNoCache
	preferences.Preferences.VerifyX509Name = post.VerifyX509Name
	preference.SavePreferences(*ovpnConfigDir, preferences)
	w.WriteHeader(http.StatusNoContent)
}
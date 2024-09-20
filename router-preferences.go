package main

import (
	"encoding/json"
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
	if !auth.HasWriteRole(app.applicationPreferences.JwtData, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var post ConfigPublicPreferencesPost
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		log.Printf("JSON.unmarshal error %v", err)
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	log.Printf("saving preferences %v", post)
	preferences := &app.applicationPreferences
	preferences.Preferences.Address = post.Address
	preferences.Preferences.ExplicitExitNotify = post.ExplicitExitNotify
	preferences.Preferences.CertificateDuration = post.CertificateDuration
	preferences.Preferences.AuthNocache = post.AuthNoCache
	preferences.Preferences.VerifyX509Name = post.VerifyX509Name
	err = preference.SavePreferences(*ovpnConfigDir, preferences)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

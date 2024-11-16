package main

import (
	"encoding/json"
	"log"
	"net/http"
	"rpiadm/backend/auth"
)

type ConfigPublicPreferencesPost struct {
	Address             string `json:"address"`
	CertificateDuration int    `json:"certificateDuration"`
	ExplicitExitNotify  bool   `json:"explicitExitNotify"`
	AuthNoCache         bool   `json:"authNoCache"`
	VerifyX509Name      bool   `json:"verifyX509Name"`
	AllowAnonymousCsr   bool   `json:"allowAnonymousCsr"`
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
	config := &app.applicationPreferences
	config.Preferences.Address = post.Address
	config.Preferences.ExplicitExitNotify = post.ExplicitExitNotify
	config.Preferences.CertificateDuration = post.CertificateDuration
	config.Preferences.AuthNocache = post.AuthNoCache
	config.Preferences.VerifyX509Name = post.VerifyX509Name
	config.Preferences.AllowAnonymousCsr = post.AllowAnonymousCsr
	err = app.applicationPreferences.SavePreferences(*ovpnConfigDir)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

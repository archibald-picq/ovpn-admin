package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/openvpn"
	"strings"
)

func extractNetmask(cidr string) string {
	// cidr = "10.8.0.0 255.255.0.0"
	parts := strings.Split(cidr, " ")
	return parts[1]
}

func (app *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var ccd openvpn.Ccd
	if r.Body == nil {
		json, _ := json.Marshal(MessagePayload{Message: "Please send a request body"})
		http.Error(w, string(json), http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		rawJson, _ := json.Marshal(MessagePayload{Message: "Can't parse JSON body"})
		http.Error(w, string(rawJson), http.StatusInternalServerError)
		return
	}

	for i, _ := range ccd.CustomRoutes {
		ccd.CustomRoutes[i].Description = strings.Trim(ccd.CustomRoutes[i].Description, " ")
	}
	for i, _ := range ccd.CustomIRoutes {
		ccd.CustomIRoutes[i].Description = strings.Trim(ccd.CustomIRoutes[i].Description, " ")
	}

	err = openvpn.UpdateCcd(*indexTxtPath, *ccdDir, *openvpnNetwork, extractNetmask(app.serverConf.Server), ccd)

	if err != nil {
		rawJson, _ := json.Marshal(MessagePayload{Message: err.Error()})
		http.Error(w, string(rawJson), http.StatusUnprocessableEntity)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	ccd, _ := json.Marshal(openvpn.ParseCcd(*ccdDir, r.FormValue("username")))
	fmt.Fprintf(w, "%s", ccd)
}

func (app *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	username := r.FormValue("username")
	device := app.getDevice(username)
	if device == nil {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("User \"%s\" not found", username)})
		http.Error(w, string(jsonRaw), http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "%s", openvpn.RenderClientConfig(
		*openvpnServer,
		app.serverConf,
		app.applicationPreferences.Preferences.ExplicitExitNotify,
		app.applicationPreferences.Preferences.AuthNocache,
		app.applicationPreferences.Preferences.Address,
		app.applicationPreferences.Preferences.VerifyX509Name,
		app.outboundIp.String(),
		app.masterCn,
		*serverConfFile,
		*easyrsaDirPath,
		app.getClientConfigTemplate(),
		*authByPassword,
		username,
	))
}

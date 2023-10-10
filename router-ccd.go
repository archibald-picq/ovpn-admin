package main

import (
	"encoding/json"
	"errors"
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
		returnErrorMessage(w, http.StatusBadRequest, errors.New("Please send a request body"))
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		returnErrorMessage(w, http.StatusInternalServerError, errors.New("Can't parse JSON body"))
		return
	}

	for i, _ := range ccd.CustomRoutes {
		ccd.CustomRoutes[i].Description = strings.Trim(ccd.CustomRoutes[i].Description, " ")
	}
	for i, _ := range ccd.CustomIRoutes {
		ccd.CustomIRoutes[i].Description = strings.Trim(ccd.CustomIRoutes[i].Description, " ")
	}

	err = openvpn.UpdateCcd(*easyrsaDirPath, *ccdDir, *openvpnNetwork, extractNetmask(app.serverConf.Server), ccd)

	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
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
		returnErrorMessage(w, http.StatusNotFound, errors.New("User "+username+" not found"))
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

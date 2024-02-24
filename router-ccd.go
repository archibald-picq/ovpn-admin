package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/shell"
	"strings"
)

func extractNetmask(cidr string) string {
	// cidr = "10.8.0.0 255.255.0.0"
	parts := strings.Split(cidr, " ")
	return parts[1]
}

func (app *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request, user string) {
	//if enableCors(&w, r) {
	//	return
	//}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		returnErrorMessage(w, http.StatusForbidden, errors.New("request forbidden"))
		return
	}

	if r.Body == nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New("please send a request body"))
		return
	}

	var ccd openvpn.Ccd
	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		returnErrorMessage(w, http.StatusInternalServerError, errors.New("can't parse JSON body"))
		return
	}

	for i, _ := range ccd.CustomRoutes {
		ccd.CustomRoutes[i].Description = strings.Trim(ccd.CustomRoutes[i].Description, " ")
	}
	for i, _ := range ccd.CustomIRoutes {
		ccd.CustomIRoutes[i].Description = strings.Trim(ccd.CustomIRoutes[i].Description, " ")
	}

	ccdDir := shell.AbsolutizePath(*serverConfFile, app.serverConf.ClientConfigDir)
	openvpnNetwork := convertNetworkMaskCidr(app.serverConf.Server)
	err = openvpn.UpdateCcd(*easyrsaDirPath, ccdDir, openvpnNetwork, extractNetmask(app.serverConf.Server), ccd, user)

	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request, username string) {
	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		returnErrorMessage(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}

	ccdDir := shell.AbsolutizePath(*serverConfFile, app.serverConf.ClientConfigDir)
	err := returnJson(w, openvpn.ParseCcd(ccdDir, username))
	if err != nil {
		log.Printf("error sending response")
	}
}

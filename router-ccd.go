package main

import (
	"encoding/json"
	"errors"
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

func (app *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request, username string) {
	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		returnErrorMessage(w, http.StatusForbidden, errors.New("request forbidden"))
		return
	}

	device := app.getDevice(username)
	if device == nil {
		returnErrorMessage(w, http.StatusNotFound, errors.New("device not found"))
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

	newCcd, err := app.applyCcd(device.Username, ccd)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	device.Ccd = newCcd
	app.triggerBroadcastUser(device)
	w.WriteHeader(http.StatusNoContent)
}
func (app *OvpnAdmin) removeCcd(commonName string) {
	openvpn.RemoveCcd(app.serverConf, commonName)
}

func (app *OvpnAdmin) applyCcd(commonName string, ccd openvpn.Ccd) (*openvpn.Ccd, error) {
	for i, _ := range ccd.CustomRoutes {
		ccd.CustomRoutes[i].Description = strings.Trim(ccd.CustomRoutes[i].Description, " ")
	}
	for i, _ := range ccd.CustomIRoutes {
		ccd.CustomIRoutes[i].Description = strings.Trim(ccd.CustomIRoutes[i].Description, " ")
	}

	openvpnNetwork := openvpn.ConvertNetworkMaskCidr(app.serverConf.Server)
	existingCcd := make([]*openvpn.Ccd, 0)
	for _, client := range app.clients {
		if client.Ccd != nil && client.Username != commonName {
			existingCcd = append(existingCcd, client.Ccd)
		}
	}
	err := openvpn.UpdateCcd(app.serverConf, openvpnNetwork, extractNetmask(app.serverConf.Server), ccd, commonName, existingCcd)
	if err != nil {
		return nil, err
	}
	// TODO: handle other options not exposed to the api
	return &ccd, nil
}

//func (app *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request, username string) {
//	if !auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)) {
//		returnErrorMessage(w, http.StatusForbidden, errors.New("forbidden"))
//		return
//	}
//
//	device := app.getDevice(username)
//	if device == nil {
//		returnErrorMessage(w, http.StatusNotFound, errors.New("device not found"))
//		return
//	}
//
//	//ccdDir := shell.AbsolutizePath(*serverConfFile, app.serverConf.ClientConfigDir)
//	//ccd := openvpn.ParseCcd(ccdDir, username)
//	err := returnJson(w, device.Ccd)
//	if err != nil {
//		log.Printf("error sending response")
//	}
//}

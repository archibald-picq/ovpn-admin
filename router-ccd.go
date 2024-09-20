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

func (app *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request, username string) (int, error) {
	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		return http.StatusForbidden, errors.New("request forbidden")
	}

	device := app.getDevice(username)
	if device == nil {
		return http.StatusNotFound, errors.New("device not found")
	}

	if r.Body == nil {
		return http.StatusBadRequest, errors.New("please send a request body")
	}

	var ccd openvpn.Ccd
	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		return http.StatusInternalServerError, errors.New("can't parse JSON body")
	}

	newCcd, err := app.applyCcd(device.Username, ccd)
	if err != nil {
		return http.StatusUnprocessableEntity, err
	}
	device.Ccd = newCcd
	app.triggerBroadcastUser(device)
	w.WriteHeader(http.StatusNoContent)
	return 0, nil
}
func (app *OvpnAdmin) removeCcd(commonName string) {
	openvpn.RemoveCcd(*serverConfFile, app.serverConf, commonName)
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
	err := openvpn.UpdateCcd(*serverConfFile, app.serverConf, openvpnNetwork, extractNetmask(app.serverConf.Server), ccd, commonName, existingCcd)
	if err != nil {
		return nil, err
	}
	// TODO: handle other options not exposed by the api
	return &ccd, nil
}

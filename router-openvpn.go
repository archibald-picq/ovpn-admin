package main

import (
	"errors"
	"log"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/shell"
)

func (app *OvpnAdmin) handleOpenvpnCommand(w http.ResponseWriter, r *http.Request) {
	log.Printf("openvpn %s, %s", r.Method, r.URL.Path)
	if enableCors(&w, r) {
		return
	}

	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		returnErrorMessage(w, http.StatusUnauthorized, errors.New("access denied"))
		return
	}

	log.Printf("call %s %s", r.Method, r.URL.Path)
	if r.URL.Path == "/api/openvpn/crl" && r.Method == "GET" {
		app.listCrl(w)
		return
	}
	returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
}

func (app *OvpnAdmin) listCrl(w http.ResponseWriter) {
	if len(app.serverConf.CrlVerify) == 0 {
		returnErrorMessage(w, http.StatusBadRequest, errors.New("no crl active"))
		return
	}
	crlPath := shell.AbsolutizePath(*serverConfFile, app.serverConf.CrlVerify)

	//log.Printf("load crl %s", crlPath)
	certs := make([]*openvpn.Certificate, 0)
	for _, client := range app.clients {
		//log.Printf("existing cert %s, serial: %s", client.Certificate.Username, client.Certificate.SerialNumber)
		certs = append(certs, client.Certificate)
	}
	crlList, err := openvpn.GetCrlList(crlPath, certs)
	if err != nil {
		log.Printf("error %v", err)
		returnErrorMessage(w, http.StatusInternalServerError, errors.New("cant parse crl"))
		return
	}
	//log.Printf("crl %v", crlList)

	returnJson(w, crlList)
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/rpi"
)

func (app *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {

		returnErrorMessage(w, http.StatusUnauthorized, errors.New("User not authorized to create certificate"))
		return
	}
	var userDefinition openvpn.UserDefinition
	err := json.NewDecoder(r.Body).Decode(&userDefinition)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("Cant parse JSON"))
		return
	}
	log.Printf("create user with %v\n", userDefinition)
	certificate, err := openvpn.UserCreateCertificate(*easyrsaDirPath, *authByPassword, *authDatabase, userDefinition)

	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	app.clients = append(app.clients, &model.Device{
		Username:         userDefinition.Username,
		ConnectionStatus: "",
		Certificate:      certificate,
		RpiState:         nil,
		Connections:      make([]*openvpn.VpnConnection, 0),
		Rpic:             make([]*rpi.RpiConnection, 0),
	})
	user := app.getDevice(userDefinition.Username)
	log.Printf("created user %v over %d clients\n", user, len(app.clients))
	w.WriteHeader(http.StatusOK)
	jsonErr, _ := json.Marshal(user)
	w.Write(jsonErr)
}

func (app *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	_ = r.ParseForm()
	err := app.userRevoke(r.FormValue("username"))
	//fmt.Fprintf(w, "%s", ret)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	err := app.userUnrevoke(r.FormValue("username"))
	if err != nil {
		log.Printf("unrevoke error %s", err.Error())
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	//if app.role == "slave" {
	//	http.Error(w, `{"status":"error"}`, http.StatusLocked)
	//	return
	//}
	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", app.userDelete(r.FormValue("username")))
}

func (app *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)
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
	err := app.userRotate(username, r.FormValue("password"))
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	//fmt.Sprintf(`{"message":"User %s successfully rotated"}`, username)
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != app.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	//archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

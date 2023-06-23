package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/openvpn"
)

func (app *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		json, _ := json.Marshal(MessagePayload{Message: "User not authorized to create certificate"})
		http.Error(w, string(json), http.StatusUnauthorized)
		return
	}
	var userDefinition openvpn.UserDefinition
	err := json.NewDecoder(r.Body).Decode(&userDefinition)
	if err != nil {
		jsonErr, _ := json.Marshal(MessagePayload{Message: "Cant parse JSON"})
		http.Error(w, string(jsonErr), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("create user with %v\n", userDefinition)
	err = openvpn.UserCreateCertificate(*easyrsaDirPath, *authByPassword, *authDatabase, userDefinition)

	if err != nil {
		jsonErr, _ := json.Marshal(MessagePayload{Message: err.Error()})
		http.Error(w, string(jsonErr), http.StatusUnprocessableEntity)
		return
	}
	user := app.getDevice(userDefinition.Username)
	log.Printf("created user %v\n", user)
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
		jsonRaw, _ := json.Marshal(MessagePayload{Message: err.Error()})
		http.Error(w, string(jsonRaw), http.StatusUnprocessableEntity)
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
		jsonRaw, _ := json.Marshal(MessagePayload{Message: err.Error()})
		http.Error(w, string(jsonRaw), http.StatusUnprocessableEntity)
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
		jsonRaw, _ := json.Marshal(MessagePayload{Message: err.Error()})
		http.Error(w, string(jsonRaw), http.StatusUnprocessableEntity)
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

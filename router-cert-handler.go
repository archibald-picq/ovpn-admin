package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/rpi"
)

func (app *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)

	if enableCors(&w, r) {
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
	certificate, err := openvpn.UserCreateCertificate(*easyrsaDirPath, *easyrsaBinPath, *authByPassword, *authDatabase, userDefinition)

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
	err = returnJson(w, user)
	if err != nil {
		log.Printf("error sending response")
	}
}

func (app *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request, username string) {

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := app.userRevoke(username)
	//fmt.Fprintf(w, "%s", ret)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request, username string) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := app.userUnrevoke(username)
	if err != nil {
		log.Printf("unrevoke error %s", err.Error())
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request, username string) {
	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := app.userDelete(username)
	if err != nil {
		returnErrorMessage(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type PasswordPayload struct {
	Password string `json:"password"`
}

func (app *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request, username string) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)

	if enableCors(&w, r) {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var passwordPayload PasswordPayload
	err := json.NewDecoder(r.Body).Decode(&passwordPayload)
	if err != nil {
		log.Printf(err.Error())
		returnErrorMessage(w, http.StatusInternalServerError, err)
		return
	}

	err = app.userRotate(username, passwordPayload.Password)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	//fmt.Sprintf(`{"message":"User %s successfully rotated"}`, username)
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request, username string) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)

	if enableCors(&w, r) {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !*authByPassword {
		returnErrorMessage(w, http.StatusNotImplemented, errors.New("not implemented"))
		return
	}

	var passwordPayload PasswordPayload
	err := json.NewDecoder(r.Body).Decode(&passwordPayload)
	if err != nil {
		log.Printf(err.Error())
		returnErrorMessage(w, http.StatusInternalServerError, err)
		return
	}

	err = app.userChangePassword(username, passwordPayload.Password)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

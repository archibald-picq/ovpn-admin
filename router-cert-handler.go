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
	if !auth.HasWriteRole(app.applicationPreferences.JwtData, r) {
		returnErrorMessage(w, http.StatusUnauthorized, errors.New("user not authorized to create certificate"))
		return
	}

	var userDefinition openvpn.UserDefinition
	err := json.NewDecoder(r.Body).Decode(&userDefinition)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("cant parse JSON in body"))
		return
	}

	if openvpn.ExistCcdCommonName(app.serverConf, userDefinition.CommonName) {
		returnErrorMessage(w, http.StatusPreconditionFailed, errors.New("conflicting existing files"))
		return
	}
	var newCcd *openvpn.Ccd
	if userDefinition.Ccd != nil {
		newCcd, err = app.applyCcd(userDefinition.CommonName, *userDefinition.Ccd)
		if err != nil {
			returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("cant setup CCD"))
			return
		}
	}

	log.Printf("create user with %v\n", userDefinition)
	if typeCa := r.URL.Query().Get("type"); typeCa == "ca" {
		if app.easyrsa.CaCertExists() {
			returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("ca already exists"))
			return
		}
		certificate, err := openvpn.CreateCaCertificate(app.easyrsa, *authByPassword, *authDatabase, userDefinition)
		if err != nil {
			//app.removeCcd(userDefinition.CommonName)
			returnErrorMessage(w, http.StatusUnprocessableEntity, err)
			return
		}
		log.Printf("certificate: %s", certificate)
		//if err = openvpn.BuildCa(app.easyrsa); err != nil {
		//	returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("Can't init PKI"))
		//	return
		//}

	} else if typeCa == "server" {
		certificate, err := app.easyrsa.CreateServerCertificate(userDefinition)
		if err != nil {
			//app.removeCcd(userDefinition.CommonName)
			returnErrorMessage(w, http.StatusUnprocessableEntity, err)
			return
		}
		log.Printf("certificate: %s", certificate)
		server := &model.Device{
			Username:         userDefinition.CommonName,
			ConnectionStatus: "",
			Certificate:      certificate,
			RpiState:         nil,
			Connections:      make([]*openvpn.VpnConnection, 0),
			Rpic:             make([]*rpi.RpiConnection, 0),
			Ccd:              newCcd,
		}

		app.easyrsa.RebuildClientRevocationList()
		//app.serverConf.MasterCn = userDefinition.CommonName
		err = returnJson(w, server)
	} else {
		certificate, err := app.easyrsa.CreateClientCertificate(userDefinition)
		if err != nil {
			app.removeCcd(userDefinition.CommonName)
			returnErrorMessage(w, http.StatusUnprocessableEntity, err)
			return
		}

		user := &model.Device{
			Username:         userDefinition.CommonName,
			ConnectionStatus: "",
			Certificate:      certificate,
			RpiState:         nil,
			Connections:      make([]*openvpn.VpnConnection, 0),
			Rpic:             make([]*rpi.RpiConnection, 0),
			Ccd:              newCcd,
		}
		app.clients = append(app.clients, user)
		log.Printf("created user %v over %d clients\n", user, len(app.clients))
		err = returnJson(w, user)
		if err != nil {
			log.Printf("error sending response")
		}
	}
}

func (app *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request, commonNameSerialNumber string) {

	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := app.userRevoke(commonNameSerialNumber)
	//fmt.Fprintf(w, "%s", ret)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request, commonNameSerialNumber string) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)

	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := app.userUnrevoke(commonNameSerialNumber)
	if err != nil {
		log.Printf("unrevoke error %s", err.Error())
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request, username string) {
	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
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

	if !auth.HasWriteRole(app.applicationPreferences.JwtData, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var userDefinition openvpn.UserDefinition
	err := json.NewDecoder(r.Body).Decode(&userDefinition)
	if err != nil {
		log.Printf(err.Error())
		returnErrorMessage(w, http.StatusInternalServerError, err)
		return
	}

	cert, err := app.userRotate(username, &userDefinition)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, err)
		return
	}
	//fmt.Sprintf(`{"message":"User %s successfully rotated"}`, username)
	//w.WriteHeader(http.StatusNoContent)
	returnJson(w, cert)
}

func (app *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request, username string) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)

	if enableCors(&w, r) {
		return
	}

	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
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

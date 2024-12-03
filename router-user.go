package main

import (
	"errors"
	"log"
	"net/http"
	"regexp"
	"rpiadm/backend/auth"
	"rpiadm/backend/model"
)

func (app *OvpnAdmin) handleUserCommand(w http.ResponseWriter, r *http.Request) {
	if enableCors(&w, r) {
		return
	}

	if r.URL.Path == "/api/user/" && r.Method == "POST" {
		app.userCreateHandler(w, r)
		return
	} else if r.URL.Path == "/api/user/" && r.Method == "GET" {
		app.userListHandler(w, r)
		return
	}

	regUser := regexp.MustCompile("^/api/user/([^/]*)/(.*)$")
	matches := regUser.FindStringSubmatch(r.URL.Path)
	if len(matches) < 2 {
		returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
		return
	}

	username := matches[1]
	cmd := matches[2]
	log.Printf("exec cmd %s for user %s", cmd, username)

	if r.Method == "PUT" {
		if cmd == "ccd" {
			retCode, e := app.userApplyCcdHandler(w, r, username)
			if e != nil {
				returnErrorMessage(w, retCode, e)
			}
			return
		}
	} else if r.Method == "GET" {
		if cmd == "conf" {
			app.buildClientOvpnConfigFile(w, r, username)
			return
		}
		//if cmd == "ccd" {
		//	app.userShowCcdHandler(w, r, username)
		//	return
		//} else
	} else if r.Method == "DELETE" {
		app.userDeleteHandler(w, r, username)
		return
	} else if r.Method == "POST" {
		if cmd == "kill" {
			app.apiConnectionKill(w, r, username)
			return
		} else if cmd == "revoke" {
			app.userRevokeHandler(w, r, username)
			return
		} else if cmd == "unrevoke" {
			app.userUnrevokeHandler(w, r, username)
			return
		} else if cmd == "rotate" {
			app.userRotateHandler(w, r, username)
			return
		} else if cmd == "change-password" {
			app.userChangePasswordHandler(w, r, username)
			return
		}
	}
	returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
}

func (app *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	//app.updateCertificateStats(openvpn.IndexTxtParserCertificate(shell.ReadFile(*indexTxtPath)))
	clients := make([]*model.Device, 0)

	for _, client := range app.clients {
		if client.Certificate.Flag != "D" && (app.serverConf == nil || client.Username != app.serverConf.MasterCn) {
			clients = append(clients, client)
		}
	}
	err := returnJson(w, clients)
	if err != nil {
		log.Printf("error sending response")
	}
}

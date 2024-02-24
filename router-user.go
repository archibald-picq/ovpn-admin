package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"rpiadm/backend/auth"
	"rpiadm/backend/model"
	"rpiadm/backend/preference"
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
			app.userApplyCcdHandler(w, r, username)
			return
		}
	} else if r.Method == "GET" {
		if cmd == "ccd" {
			app.userShowCcdHandler(w, r, username)
			return
		} else if cmd == "conf" {
			app.buildClientConf(w, r, username)
			return
		}
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

func (app *OvpnAdmin) handleAdminAccount(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s\n", r.RemoteAddr, r.RequestURI)

	if enableCors(&w, r) {
		return
	}

	firstCreateUser := false
	if len(app.applicationPreferences.Users) != 0 {
		// bypass auth if there is no user yet
		if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else {
		firstCreateUser = true
	}
	log.Printf("%s admin account %s", r.Method, r.URL)
	re := regexp.MustCompile("^/api/config/admin/(.*)$")

	if r.Method == "DELETE" {
		matches := re.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			err := preference.DeleteUser(*ovpnConfigDir, &app.applicationPreferences, matches[1])
			if err != nil {
				returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to delete user %s", err)))
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
			return
		}
	}

	var adminAccountUpdate preference.AdminAccountUpdate
	err := json.NewDecoder(r.Body).Decode(&adminAccountUpdate)
	if err != nil {
		log.Printf(err.Error())
		return
	}

	if r.Method == "PUT" {
		matches := re.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			err := preference.UpdateUser(*ovpnConfigDir, &app.applicationPreferences, matches[1], adminAccountUpdate)
			if err != nil {
				returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to delete user %s", err)))
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
			return
		}
	}

	if r.URL.Path != "/api/config/admin/" {
		returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
		return
	}

	err = preference.CreateUser(*ovpnConfigDir, &app.applicationPreferences, adminAccountUpdate)
	if err != nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to delete user %s", err)))
		return
	}

	if firstCreateUser {
		cookie, expirationTime, err := auth.BuildJwtCookie(&app.applicationPreferences, adminAccountUpdate.Username)
		if err != nil {
			returnErrorMessage(w, http.StatusBadRequest, err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth",
			Value:    cookie,
			Expires:  expirationTime,
			HttpOnly: true,
			Path:     "/",
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)

	if enableCors(&w, r) {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	//app.updateCertificateStats(openvpn.IndexTxtParserCertificate(shell.ReadFile(*indexTxtPath)))
	clients := make([]*model.Device, 0)

	for _, client := range app.clients {
		if client.Certificate.Flag != "D" {
			clients = append(clients, client)
		}
	}
	err := returnJson(w, clients)
	if err != nil {
		log.Printf("error sending response")
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"rpiadm/backend/auth"
	"rpiadm/backend/preference"
)

func (app *OvpnAdmin) saveAdminAccount(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s\n", r.RemoteAddr, r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
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
				jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Failed to delete user %s", err)})
				http.Error(w, string(jsonRaw), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: "Bad request"})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
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
				jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Failed to delete user %s", err)})
				http.Error(w, string(jsonRaw), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: "Bad request"})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
			return
		}
	}

	if r.URL.Path != "/api/config/admin/" {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Bad request"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	err = preference.CreateUser(*ovpnConfigDir, &app.applicationPreferences, adminAccountUpdate)
	if err != nil {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Failed to delete user %s", err)})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	if firstCreateUser {
		cookie, expirationTime, err := auth.BuildJwtCookie(&app.applicationPreferences, adminAccountUpdate.Username)
		if err != nil {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: err.Error()})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
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
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	//app.updateCertificateStats(openvpn.IndexTxtParserCertificate(shell.ReadFile(*indexTxtPath)))
	usersList, _ := json.Marshal(app.clients)
	_, _ = w.Write(usersList)
	//fmt.Fprintf(w, "%s", updateClientList)
}

func (app *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	if !*authByPassword {
		jsonErr, _ := json.Marshal(MessagePayload{Message: "Not implemented"})
		http.Error(w, string(jsonErr), http.StatusNotImplemented)
		return
	}
	err := app.userChangePassword(r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		jsonErr, _ := json.Marshal(MessagePayload{Message: err.Error()})
		http.Error(w, string(jsonErr), http.StatusUnprocessableEntity)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"rpiadm/backend/auth"
	"rpiadm/backend/preference"
)

func (app *OvpnAdmin) handleAdminAccount(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s\n", r.RemoteAddr, r.RequestURI)

	firstCreateUser := false
	if len(app.applicationPreferences.Users) != 0 {
		// bypass auth if there is no user yet
		if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
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
			err := app.applicationPreferences.DeleteUser(*ovpnConfigDir, matches[1])
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
		returnErrorMessage(w, http.StatusBadRequest, err)
		return
	}

	if r.Method == "PUT" {
		matches := re.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			err := app.applicationPreferences.UpdateUser(*ovpnConfigDir, matches[1], adminAccountUpdate)
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

	err = app.applicationPreferences.CreateUser(*ovpnConfigDir, adminAccountUpdate)
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

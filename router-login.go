package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"rpiadm/backend/auth"
	"time"
)

type AuthenticatePayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (app *OvpnAdmin) authenticate(w http.ResponseWriter, r *http.Request) {
	ok, _ := auth.JwtUsername(app.applicationPreferences.JwtData, r)
	if ok {
		returnErrorMessage(w, http.StatusForbidden, errors.New("already authenticated"))
		return
	}

	var authPayload AuthenticatePayload
	err := json.NewDecoder(r.Body).Decode(&authPayload)
	if err != nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("can't decode auth payload %s", err)))
		return
	}

	err = auth.Authenticate(&app.applicationPreferences, authPayload.Username, authPayload.Password)
	if err != nil {
		returnErrorMessage(w, http.StatusBadRequest, err)
		return
	}

	cookie, expirationTime, err := auth.BuildJwtCookie(&app.applicationPreferences, authPayload.Username)
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
	err = returnJson(w, auth.GetUserProfile(&app.applicationPreferences, authPayload.Username))
	if err != nil {
		log.Printf("error sending response")
	}
}

func (app *OvpnAdmin) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})
	w.WriteHeader(http.StatusNoContent)
}

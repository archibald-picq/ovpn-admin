package main

import (
	"encoding/json"
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
	ok, _ := auth.JwtUsername(app.applicationPreferences.JwtData, getAuthCookie(r))
	if ok {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Already authenticated"})
		http.Error(w, string(jsonRaw), http.StatusForbidden)
		return
	}

	var authPayload AuthenticatePayload
	err := json.NewDecoder(r.Body).Decode(&authPayload)
	if err != nil {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Can't decode auth payload %s", err)})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	cookie, expirationTime, err := auth.Authenticate(&app.applicationPreferences, authPayload.Username, authPayload.Password)

	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    cookie,
		Expires:  expirationTime,
		HttpOnly: true,
	})
	rawJson, _ := json.Marshal(auth.GetUserProfile(&app.applicationPreferences, authPayload.Username))
	_, err = w.Write(rawJson)
	if err != nil {
		log.Printf("Fail to write response")
		return
	}
}

func (app *OvpnAdmin) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusNoContent)
}

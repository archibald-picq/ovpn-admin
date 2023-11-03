package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"rpiadm/backend/auth"
)

type ConnectionId struct {
	ClientId int64 `json:"clientId"`
}

func (app *OvpnAdmin) apiConnectionKill(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.RemoteAddr, r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var req ConnectionId
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("Cant parse JSON"))
		return
	}

	for _, c := range app.clients {
		for _, conn := range c.Connections {
			if conn.ClientId == req.ClientId {
				log.Printf("killing collection %v", conn)
				if err := app.killAndRemoveConnection(c, conn); err != nil {
					returnErrorMessage(w, http.StatusInternalServerError, err)
					return
				}
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

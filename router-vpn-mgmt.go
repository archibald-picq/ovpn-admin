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

func (app *OvpnAdmin) apiConnectionKill(w http.ResponseWriter, r *http.Request, username string) {
	//log.Printf("%s %s", r.RemoteAddr, r.RequestURI)
	//if enableCors(&w, r) {
	//	return
	//}

	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var req ConnectionId
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("can't parse JSON"))
		return
	}

	for _, c := range app.clients {
		for _, conn := range c.Connections {
			log.Printf("compare '%d' and '%d'", conn.ClientId, req.ClientId)
			if conn.ClientId == req.ClientId {
				if c.Username != username {
					returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("this connection does not belong to this user"))
					return
				}
				log.Printf("killing collection %v", conn)
				if err := app.killAndRemoveConnection(c, conn); err != nil {
					returnErrorMessage(w, http.StatusInternalServerError, err)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
	}
	returnErrorMessage(w, http.StatusBadRequest, errors.New("connection not found"))
}

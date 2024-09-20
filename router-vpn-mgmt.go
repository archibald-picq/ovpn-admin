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

	if !auth.HasWriteRole(app.applicationPreferences.JwtData, r) {
		returnErrorMessage(w, http.StatusForbidden, errors.New("access denied"))
		return
	}
	var req ConnectionId
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		returnErrorMessage(w, http.StatusUnprocessableEntity, errors.New("can't parse JSON"))
		return
	}

	client, conn := app.getUserConnection(username, req.ClientId)
	if client == nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New("connection not found"))
	}

	log.Printf("killing collection %v", conn)
	if err := app.killAndRemoveConnection(client, conn); err != nil {
		returnErrorMessage(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

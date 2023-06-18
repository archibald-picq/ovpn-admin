package main

import (
	"encoding/json"
	"net/http"
)

func (app *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	app.updateClientList(indexTxtParser(fRead(*indexTxtPath)))
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
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
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

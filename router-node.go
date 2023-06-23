package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"rpiadm/backend/auth"
	"rpiadm/backend/rpi"
)

func (app *OvpnAdmin) handleReadNodeConfig(w http.ResponseWriter, r *http.Request) {
	//log.Debug(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	re := regexp.MustCompile("^/api/node/(.*)$")
	matches := re.FindStringSubmatch(r.URL.Path)
	log.Printf("get config for node %s (%v)", r.URL.Path, matches)
	if len(matches) > 0 {
		payload, err := rpi.ReadNodeConfig(*ovpnConfigDir, matches[1])
		if err != nil {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Failed read config for user %s: %¨s", matches[1], err)})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
			return
		}
		rawJson, _ := json.Marshal(payload)
		//w.WriteHeader(http.StatusOK)
		w.Write(rawJson)
		return
	} else {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Bad request"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

}

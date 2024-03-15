package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"rpiadm/backend/auth"
	"rpiadm/backend/rpi"
)

func (app *OvpnAdmin) handleNodeCommand(w http.ResponseWriter, r *http.Request) {
	//log.Debug(r.RemoteAddr, " ", r.RequestURI)

	if enableCors(&w, r) {
		return
	}

	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	re := regexp.MustCompile("^/api/node/(.*)$")
	matches := re.FindStringSubmatch(r.URL.Path)
	log.Printf("get config for node %s (%v)", r.URL.Path, matches)
	if len(matches) > 0 {
		payload, err := rpi.ReadNodeConfig(*ovpnConfigDir, matches[1])
		if err != nil {
			returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("Failed read config for user %s: %¨s", matches[1], err)))
			return
		}
		err = returnJson(w, payload)
		if err != nil {
			log.Printf("error sending response")
		}
		return
	} else {
		returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
		return
	}

}

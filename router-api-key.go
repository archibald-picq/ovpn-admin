package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"net/http"
	"regexp"
	"rpiadm/backend/preference"
)

func (app *OvpnAdmin) handleApiKey(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s\n", r.RemoteAddr, r.RequestURI)

	log.Printf("%s api key %s", r.Method, r.URL)
	regId := regexp.MustCompile("^/api/config/api-key/(.*)$")

	if r.Method == "DELETE" {
		matches := regId.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			id, err := uuid.Parse(matches[1])
			if err != nil {
				returnErrorMessage(w, http.StatusBadRequest, errors.New("invalid uuid"))
				return
			}
			err = preference.DeleteApiKey(*ovpnConfigDir, &app.applicationPreferences, id)
			if err != nil {
				returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to delete api key %s", err)))
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
			return
		}
	}

	var apiKeyUpdateUpdate preference.ApiKeyUpdate
	err := json.NewDecoder(r.Body).Decode(&apiKeyUpdateUpdate)
	if err != nil {
		log.Printf(err.Error())
		return
	}

	if r.Method == "PUT" {
		matches := regId.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			id, err := uuid.Parse(matches[1])
			if err != nil {
				returnErrorMessage(w, http.StatusBadRequest, errors.New("invalid uuid"))
				return
			}
			apiKey, err := preference.UpdateApiKey(*ovpnConfigDir, &app.applicationPreferences, id, apiKeyUpdateUpdate)
			if err != nil {
				returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to delete api key %s", err)))
				return
			}
			err = returnJson(w, apiKeyMapper(*apiKey))
			if err != nil {
				log.Printf("error sending response")
			}
			return
		} else {
			returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
			return
		}
	} else if r.Method == "POST" {

		if r.URL.Path == "/api/config/api-key/" {

			apiKey, err := preference.CreateApiKey(*ovpnConfigDir, &app.applicationPreferences, apiKeyUpdateUpdate)
			if err != nil {
				returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to create api key %s", err)))
				return
			}
			err = returnJson(w, apiKeyMapper(*apiKey))
			if err != nil {
				log.Printf("error sending response")
			}
			return
		}

	}
	returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
}

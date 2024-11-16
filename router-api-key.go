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
			app.deleteApiKeyById(w, matches[1])
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
			app.updateApiKeyById(w, matches[1], apiKeyUpdateUpdate)
			return
		} else {
			returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
			return
		}
	} else if r.Method == "POST" && r.URL.Path == "/api/config/api-key/" {
		app.CreateApiKey(w, apiKeyUpdateUpdate)
		return
	}
	returnErrorMessage(w, http.StatusBadRequest, errors.New("bad request"))
}

func (app *OvpnAdmin) CreateApiKey(w http.ResponseWriter, update preference.ApiKeyUpdate) {
	apiKey, err := preference.CreateApiKey(*ovpnConfigDir, &app.applicationPreferences, update)
	if err != nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to create api key %s", err)))
		return
	}
	err = returnJson(w, preference.ApiKeyMapper(*apiKey))
	if err != nil {
		log.Printf("error sending response")
	}
}

func (app *OvpnAdmin) deleteApiKeyById(w http.ResponseWriter, idStr string) {
	id, err := uuid.Parse(idStr)
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
}

func (app *OvpnAdmin) updateApiKeyById(w http.ResponseWriter, idStr string, update preference.ApiKeyUpdate) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New("invalid uuid"))
		return
	}
	apiKey, err := preference.UpdateApiKey(*ovpnConfigDir, &app.applicationPreferences, id, update)
	if err != nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to delete api key %s", err)))
		return
	}
	err = returnJson(w, preference.ApiKeyMapper(*apiKey))
	if err != nil {
		log.Printf("error sending response")
	}
}

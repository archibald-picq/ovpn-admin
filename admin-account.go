package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"regexp"
	log "github.com/sirupsen/logrus"
)
type AdminAccountUpdate struct {
	 Username    string `json:"username"`
	 Name        string `json:"name"`
	 Password    string `json:"password"`
}

func (app *OvpnAdmin) saveAdminAccount(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	log.Printf("%s admin account %s", r.Method, r.URL)
	re := regexp.MustCompile("^/api/config/admin/(.*)$")

	if r.Method == "DELETE" {
		matches := re.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			err := app.deleteUser(matches[1])
			if err != nil {
				jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Failed to delete user %s", err)})
				http.Error(w, string(jsonRaw), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: "Bad request"})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
			return
		}
	}

	var adminAccountUpdate AdminAccountUpdate
	err := json.NewDecoder(r.Body).Decode(&adminAccountUpdate)
	if err != nil {
		log.Errorln(err)
	}

	if r.Method == "PUT" {
		matches := re.FindStringSubmatch(r.URL.Path)
		if len(matches) > 0 {
			err := app.updateUser(matches[1], adminAccountUpdate)
			if err != nil {
				jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Failed to delete user %s", err)})
				http.Error(w, string(jsonRaw), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: "Bad request"})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
			return
		}
	}

	if r.URL.Path != "/api/config/admin/" {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Bad request"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	err = app.createUser(adminAccountUpdate)
	if err != nil {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Failed to delete user %s", err)})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) deleteUser(username string) error {
	for i, u := range app.applicationPreferences.Users {
		if u.Username == username {
			app.applicationPreferences.Users = RemoveIndex(app.applicationPreferences.Users, i)
			return app.savePreferences()
		}
	}
	return errors.New(fmt.Sprintf("User %s not found", username))
}

func (app *OvpnAdmin) updateUser(username string, updates AdminAccountUpdate) error {
	for i, u := range app.applicationPreferences.Users {
		if u.Username == username {
			app.applicationPreferences.Users[i].Username = updates.Username
			app.applicationPreferences.Users[i].Name = updates.Name
			if len(updates.Password) > 0 {
				encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Password), bcrypt.DefaultCost)
				if err != nil {
					return err
				}
				app.applicationPreferences.Users[i].Password = string(encoded)
			}
			return app.savePreferences()
		}
	}
	return errors.New(fmt.Sprintf("User %s not found", username))
}

func (app *OvpnAdmin) createUser(updates AdminAccountUpdate) error {
	for _, u := range app.applicationPreferences.Users {
		if u.Username == updates.Username {
			return errors.New(fmt.Sprintf("User %s already exists", updates.Username))
		}
	}
	encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	app.applicationPreferences.Users = append(app.applicationPreferences.Users, Account{
		Username: updates.Username,
		Name: updates.Name,
		Password: string(encoded),
	})
	return app.savePreferences()
}

func RemoveIndex(s []Account, index int) []Account {
	return append(s[:index], s[index+1:]...)
}

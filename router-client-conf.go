package main

import (
	"errors"
	"log"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/openvpn"
	"text/template"
)

func (app *OvpnAdmin) buildClientOvpnConfigFile(w http.ResponseWriter, r *http.Request, username string) {
	//for name, values := range r.Header {
	//	for _, value := range values {
	//		fmt.Printf("%s: %s\n", name, value)
	//	}
	//	//log.Printf("header %v", values)
	//}
	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		credentials := getBasicAuth(r)
		if apiKey := auth.HasValidApiKey(app.applicationPreferences.ApiKeys, credentials); apiKey == nil {
			if len(credentials) != 0 {
				w.WriteHeader(http.StatusForbidden)
			} else {
				w.Header().Set("WWW-Authenticate", "Basic realm=\"Please login or provide api-key\"")
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		} else {
			log.Printf("use api key '%s'", apiKey.Comment)
		}
	}

	device := app.getDevice(username)
	if device == nil {
		returnErrorMessage(w, http.StatusNotFound, errors.New("User "+username+" not found"))
		return
	}

	w.Write(openvpn.RenderClientConfig(
		*openvpnServer,
		app.serverConf,
		app.applicationPreferences.Preferences.ExplicitExitNotify,
		app.applicationPreferences.Preferences.AuthNocache,
		app.applicationPreferences.Preferences.Address,
		app.applicationPreferences.Preferences.VerifyX509Name,
		app.outboundIp.String(),
		app.serverConf.MasterCn,
		*serverConfFile,
		*easyrsaDirPath,
		app.getClientConfigTemplate(),
		*authByPassword,
		username,
	))
}

func (app *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTpl, clientConfigTplErr := templates.ReadFile("templates/client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Printf("clientConfigTpl not found in templates box")
		}
		return template.Must(template.New("client-config").Parse(string(clientConfigTpl)))
	}
}

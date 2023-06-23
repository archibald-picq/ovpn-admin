package main

import (
	"encoding/json"
	"fmt"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	"log"
	"net"
	"net/http"
	"rpiadm/backend/auth"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/shell"
	"strings"
)

type ServerSavePayload struct {
	Server                     string          `json:"server"`
	ForceGatewayIpv4           bool            `json:"forceGatewayIpv4"`
	ForceGatewayIpv4ExceptDhcp bool            `json:"forceGatewayIpv4ExceptDhcp"`
	ForceGatewayIpv4ExceptDns  bool            `json:"forceGatewayIpv4ExceptDns"`
	ServerIpv6                 string          `json:"serverIpv6"`
	ForceGatewayIpv6           bool            `json:"forceGatewayIpv6"`
	ClientToClient             bool            `json:"clientToClient"`
	DuplicateCn                bool            `json:"duplicateCn"`
	CompLzo                    bool            `json:"compLzo"`
	Auth                       string          `json:"auth"`
	EnableMtu                  bool            `json:"enableMtu"`
	TunMtu                     int             `json:"tunMtu"`
	Routes                     []openvpn.Route `json:"routes"`
	DnsIpv4                    string          `json:"dnsIpv4"`
	DnsIpv6                    string          `json:"dnsIpv6"`
}

func convertNetworkMaskCidr(addrMask string) string {
	parts := strings.Fields(addrMask)
	pref := ipaddr.NewIPAddressString(parts[1]).GetAddress().GetBlockMaskPrefixLen(true)
	return fmt.Sprintf("%s/%d", parts[0], pref.Len())
}

func convertCidrNetworkMask(cidr string) string {
	ipv4Addr, ipv4Net, _ := net.ParseCIDR(cidr)
	mask := fmt.Sprintf("%d.%d.%d.%d", ipv4Net.Mask[0], ipv4Net.Mask[1], ipv4Net.Mask[2], ipv4Net.Mask[3])
	return fmt.Sprintf("%s %s", ipv4Addr, mask)
}

func (app *OvpnAdmin) exportPublicSettings() *model.ConfigPublicSettings {
	log.Println("exporting settings %v", app.serverConf)
	var settings = new(model.ConfigPublicSettings)
	settings.Server = convertNetworkMaskCidr(app.serverConf.Server)
	settings.ForceGatewayIpv4 = app.serverConf.ForceGatewayIpv4
	settings.ForceGatewayIpv4ExceptDhcp = app.serverConf.ForceGatewayIpv4ExceptDhcp
	settings.ForceGatewayIpv4ExceptDns = app.serverConf.ForceGatewayIpv4ExceptDns
	settings.ServerIpv6 = app.serverConf.ServerIpv6
	settings.ForceGatewayIpv6 = app.serverConf.ForceGatewayIpv6
	settings.DuplicateCn = app.serverConf.DuplicateCn
	settings.ClientToClient = app.serverConf.ClientToClient
	settings.CompLzo = app.serverConf.CompLzo
	settings.Routes = app.serverConf.Routes
	settings.Auth = app.serverConf.Auth
	settings.Pushs = app.serverConf.Push
	settings.EnableMtu = app.serverConf.EnableMtu
	settings.TunMtu = app.serverConf.TunMtu
	settings.DnsIpv4 = app.serverConf.DnsIpv4
	settings.DnsIpv6 = app.serverConf.DnsIpv6
	//settings.Routes = make([]string, 0)
	//for _, routes := range app.serverConf.routes {
	//	settings.Routes = append(settings.Routes, convertNetworkMaskCidr(routes))
	//}
	return settings
}

func (app *OvpnAdmin) exportPublicPreferences() *model.ConfigPublicPreferences {
	var preferences = new(model.ConfigPublicPreferences)
	preferences.Address = app.applicationPreferences.Preferences.Address
	preferences.DefaultAddress = fmt.Sprintf("%s:%d", app.outboundIp, app.serverConf.Port)
	preferences.CertificateDuration = 3600 * 24 * 365 * 10 // 10 years
	preferences.ExplicitExitNotify = app.applicationPreferences.Preferences.ExplicitExitNotify
	preferences.AuthNoCache = app.applicationPreferences.Preferences.AuthNocache
	preferences.VerifyX509Name = app.applicationPreferences.Preferences.VerifyX509Name

	if app.applicationPreferences.Preferences.CertificateDuration > 0 {
		preferences.CertificateDuration = app.applicationPreferences.Preferences.CertificateDuration
	}

	for _, u := range app.applicationPreferences.Users {
		preferences.Users = append(preferences.Users, model.ConfigPublicAccount{Username: u.Username, Name: u.Name})
	}

	return preferences
}

func (app *OvpnAdmin) showConfig(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	log.Printf("config %v", app.serverConf)
	configPublic := new(model.ConfigPublic)
	configPublic.Openvpn.Url = ""

	ok, jwtUsername := auth.JwtUsername(app.applicationPreferences.JwtData, getAuthCookie(r))
	if ok {
		configPublic.User = auth.GetUserProfile(&app.applicationPreferences, jwtUsername)
		configPublic.Openvpn.Settings = app.exportPublicSettings()
		configPublic.Openvpn.Preferences = app.exportPublicPreferences()
	}

	if len(app.applicationPreferences.Users) == 0 {
		b := true
		configPublic.Openvpn.Unconfigured = &b
	}

	rawJson, _ := json.Marshal(configPublic)
	_, err := w.Write(rawJson)
	if err != nil {
		log.Println("Fail to write response")
		return
	}
	//fmt.Fprintf(w, `{%s"openvpn":{"url":""}}`, user)
}

func (app *OvpnAdmin) postServerConfig(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	if hasReadRole := auth.JwtHasReadRole(app.applicationPreferences.JwtData, getAuthCookie(r)); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var savePayload ServerSavePayload
	if r.Body == nil {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Please send a request body"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&savePayload)
	if err != nil {
		log.Printf("failed to decode body %v", err)
	}

	// check addresses in post payload
	for _, route := range savePayload.Routes {
		if net.ParseIP(route.Address) == nil {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Invalid route.address %s", route.Address)})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
			return
		}

		if net.ParseIP(route.Netmask) == nil {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Invalid route.netmasl %s", route.Netmask)})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
			return
		}
	}

	// store in temporary object
	conf := app.serverConf
	conf.Server = convertCidrNetworkMask(savePayload.Server)
	conf.ForceGatewayIpv4 = savePayload.ForceGatewayIpv4
	conf.ForceGatewayIpv4ExceptDhcp = savePayload.ForceGatewayIpv4ExceptDhcp
	conf.ForceGatewayIpv4ExceptDns = savePayload.ForceGatewayIpv4ExceptDns
	conf.ServerIpv6 = savePayload.ServerIpv6
	conf.ForceGatewayIpv6 = savePayload.ForceGatewayIpv6
	conf.CompLzo = savePayload.CompLzo
	conf.ClientToClient = savePayload.ClientToClient
	conf.DuplicateCn = savePayload.DuplicateCn
	conf.Routes = savePayload.Routes
	conf.Auth = savePayload.Auth
	conf.EnableMtu = savePayload.EnableMtu
	conf.TunMtu = savePayload.TunMtu
	conf.DnsIpv4 = savePayload.DnsIpv4
	conf.DnsIpv6 = savePayload.DnsIpv6

	backupFile := fmt.Sprintf("%s.backup", *serverConfFile)

	// make a backup of the original OpenVPN config file
	err = shell.FileCopy(*serverConfFile, backupFile)
	if err != nil {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Can't backup config file"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	// write a temporary config file over the original one
	err = shell.WriteFile(*serverConfFile, openvpn.BuildConfig(conf))
	if err != nil {
		shell.FileCopy(backupFile, *serverConfFile)
		jsonRaw, _ := json.Marshal(MessagePayload{Message: err.Error()})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	err = app.restartServer()
	if err != nil {
		// rollback config and restart server on error
		shell.FileCopy(backupFile, *serverConfFile)
		err = app.restartServer()
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "restarted"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	// store the working config in memory
	app.serverConf.Server = conf.Server
	app.serverConf.ForceGatewayIpv4 = conf.ForceGatewayIpv4
	app.serverConf.ForceGatewayIpv4ExceptDhcp = conf.ForceGatewayIpv4ExceptDhcp
	app.serverConf.ForceGatewayIpv4ExceptDns = conf.ForceGatewayIpv4ExceptDns
	app.serverConf.ServerIpv6 = conf.ServerIpv6
	app.serverConf.ForceGatewayIpv6 = conf.ForceGatewayIpv6
	app.serverConf.CompLzo = conf.CompLzo
	app.serverConf.ClientToClient = conf.ClientToClient
	app.serverConf.DuplicateCn = conf.DuplicateCn
	app.serverConf.Auth = conf.Auth
	app.serverConf.EnableMtu = conf.EnableMtu
	app.serverConf.TunMtu = conf.TunMtu
	app.serverConf.DnsIpv4 = conf.DnsIpv4
	app.serverConf.DnsIpv6 = conf.DnsIpv6

	w.WriteHeader(http.StatusNoContent)
}

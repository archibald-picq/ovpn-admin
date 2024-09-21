package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/alessio/shellescape"
	"log"
	"net"
	"net/http"
	"regexp"
	"rpiadm/backend/auth"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/shell"
	"strings"
)

type ServerSavePayload struct {
	ServerCertificate          *string         `json:"serverCertificate"`
	Server                     string          `json:"server"`
	ForceGatewayIpv4           bool            `json:"forceGatewayIpv4"`
	ForceGatewayIpv4ExceptDhcp bool            `json:"forceGatewayIpv4ExceptDhcp"`
	ForceGatewayIpv4ExceptDns  bool            `json:"forceGatewayIpv4ExceptDns"`
	ServerIpv6                 *string         `json:"serverIpv6"`
	ForceGatewayIpv6           bool            `json:"forceGatewayIpv6"`
	ClientToClient             bool            `json:"clientToClient"`
	DuplicateCn                bool            `json:"duplicateCn"`
	CompLzo                    bool            `json:"compLzo"`
	Auth                       string          `json:"auth"`
	EnableMtu                  bool            `json:"enableMtu"`
	TunMtu                     int             `json:"tunMtu"`
	Routes                     []openvpn.Route `json:"routes"`
	RoutesPush                 []openvpn.Route `json:"routesPush"`
	DnsIpv4                    *string         `json:"dnsIpv4"`
	DnsIpv6                    *string         `json:"dnsIpv6"`
}

func convertCidrNetworkMask(cidr string) string {
	ipv4Addr, ipv4Net, _ := net.ParseCIDR(cidr)
	mask := fmt.Sprintf("%d.%d.%d.%d", ipv4Net.Mask[0], ipv4Net.Mask[1], ipv4Net.Mask[2], ipv4Net.Mask[3])
	return fmt.Sprintf("%s %s", ipv4Addr, mask)
}

func (app *OvpnAdmin) exportServiceSettings() *model.ConfigPublicSettings {
	if app.serverConf == nil {
		return nil
	}
	//log.Println("exporting settings %v", app.serverConf)
	var settings = new(model.ConfigPublicSettings)
	settings.ServiceName = app.serverConf.ServiceName
	settings.Server = openvpn.ConvertNetworkMaskCidr(app.serverConf.Server)
	settings.ForceGatewayIpv4 = app.serverConf.ForceGatewayIpv4
	settings.ForceGatewayIpv4ExceptDhcp = app.serverConf.ForceGatewayIpv4ExceptDhcp
	settings.ForceGatewayIpv4ExceptDns = app.serverConf.ForceGatewayIpv4ExceptDns
	settings.ServerIpv6 = app.serverConf.ServerIpv6
	settings.ForceGatewayIpv6 = app.serverConf.ForceGatewayIpv6
	settings.DuplicateCn = app.serverConf.DuplicateCn
	settings.ClientToClient = app.serverConf.ClientToClient
	settings.CompLzo = app.serverConf.CompLzo
	settings.Routes = app.serverConf.Routes
	settings.RoutesPush = app.serverConf.RoutesPush
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

func (app *OvpnAdmin) buildDefaultAddress() string {
	if app.serverConf != nil {
		return fmt.Sprintf("%s:%d", app.outboundIp, app.serverConf.Port)
	} else {
		return fmt.Sprintf("%s:1194", app.outboundIp)
	}
}

func (app *OvpnAdmin) exportPublicPreferences() *model.ConfigPublicPreferences {
	var preferences = new(model.ConfigPublicPreferences)
	preferences.Address = app.applicationPreferences.Preferences.Address
	preferences.DefaultAddress = app.buildDefaultAddress()
	preferences.CertificateDuration = 3600 * 24 * 365 * 10 // 10 years
	preferences.ExplicitExitNotify = app.applicationPreferences.Preferences.ExplicitExitNotify
	preferences.AuthNoCache = app.applicationPreferences.Preferences.AuthNocache
	preferences.VerifyX509Name = app.applicationPreferences.Preferences.VerifyX509Name
	preferences.ApiKeys = make([]model.ConfigPublicApiKey, 0)

	if app.applicationPreferences.Preferences.CertificateDuration > 0 {
		preferences.CertificateDuration = app.applicationPreferences.Preferences.CertificateDuration
	}

	for _, u := range app.applicationPreferences.Users {
		preferences.Users = append(preferences.Users, model.ConfigPublicAccount{Username: u.Username, Name: u.Name})
	}

	for _, u := range app.applicationPreferences.ApiKeys {
		preferences.ApiKeys = append(preferences.ApiKeys, apiKeyMapper(u))
	}

	return preferences
}

func (app *OvpnAdmin) handleConfigCommand(w http.ResponseWriter, r *http.Request) {
	log.Printf("config %s, %s", r.Method, r.URL.Path)
	if enableCors(&w, r) {
		return
	}

	if r.URL.Path == "/api/config" && r.Method == "GET" {
		app.showUserConfig(w, r)
		return
	}

	//if r.URL.Path == "/api/config/settings/save" {
	//	app.saveServerConfig(w, r)
	//	return
	//}

	if r.Method == "POST" && r.URL.Path == "/api/config/preferences/save" {
		app.postPreferences(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/config/admin/") {
		app.handleAdminAccount(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/config/api-key/") {
		app.handleApiKey(w, r)
		return
	}

	regServer := regexp.MustCompile("^/api/config/service/([^/]*)/save$")
	matches := regServer.FindStringSubmatch(r.URL.Path)
	if len(matches) >= 1 {
		serviceName := matches[1]
		app.saveServerConfig(w, r, serviceName)
		return
	}

	returnErrorMessage(w, http.StatusNotFound, errors.New("path not found"))
}

func (app *OvpnAdmin) showUserConfig(w http.ResponseWriter, r *http.Request) {
	b := true

	//log.Printf("config %v", app.serverConf)
	configPublic := new(model.ConfigPublic)
	configPublic.Openvpn.Url = ""

	ok, jwtUsername := auth.JwtUsername(app.applicationPreferences.JwtData, r)
	if ok {
		configPublic.User = auth.GetUserProfile(&app.applicationPreferences, jwtUsername)
		configPublic.Openvpn.Settings = app.exportServiceSettings()
		configPublic.Openvpn.Preferences = app.exportPublicPreferences()
	}

	// first user: allow create admin account
	if len(app.applicationPreferences.Users) == 0 {
		configPublic.Openvpn.Unconfigured = &b
	}

	// no server settings ? so no server daemon configured
	if configPublic.Openvpn.Settings == nil {
		configPublic.Openvpn.ServerSetup = app.buildServerSetupConfig()
	}

	err := returnJson(w, configPublic)
	if err != nil {
		log.Println("Fail to write response")
		return
	}
	//fmt.Fprintf(w, `{%s"openvpn":{"url":""}}`, user)
}
func (app *OvpnAdmin) buildServerSetupConfig() *openvpn.ServerConfigVpn {
	var serverSetup openvpn.ServerConfigVpn
	serverSetup.ServiceName = "server"
	serverSetup.PkiPath = app.easyrsa.EasyrsaDirPath + "/pki"
	if openvpn.IsPkiInited(app.easyrsa) {
		certs := openvpn.IndexTxtParserCertificate(app.easyrsa)
		count := len(certs)
		serverSetup.PkiInit = &count
		serverSetup.ServerCert = openvpn.FindFirstServerCertIfExists(app.easyrsa, certs)
	} else {
		serverSetup.ServerCert = nil
	}
	serverSetup.DhPem = openvpn.DhPemExists(app.easyrsa)
	serverSetup.CaCert = openvpn.ReadCaCertIfExists(app.easyrsa)
	return &serverSetup
}
func (app *OvpnAdmin) restartServer(serviceName string) error {
	cmd := fmt.Sprintf("systemctl restart openvpn@%s.service", shellescape.Quote(serviceName))
	log.Printf("cmd %s", cmd)
	ret, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("cmd fails with: %s", ret)
	}
	return err
}

func (app *OvpnAdmin) saveServerConfig(w http.ResponseWriter, r *http.Request, serviceName string) {

	if !auth.HasReadRole(app.applicationPreferences.JwtData, r) {
		returnErrorMessage(w, http.StatusForbidden, errors.New("Access denied"))
		return
	}

	if r.Body == nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New("Please send a request body"))
		return
	}

	var savePayload ServerSavePayload
	err := json.NewDecoder(r.Body).Decode(&savePayload)
	if err != nil {
		returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("failed to decode body %v", err)))
		return
	}

	// check addresses in post payload
	for _, route := range savePayload.Routes {
		if net.ParseIP(route.Address) == nil {
			returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("Invalid route.address %s", route.Address)))
			return
		}

		if net.ParseIP(route.Netmask) == nil {
			returnErrorMessage(w, http.StatusBadRequest, errors.New(fmt.Sprintf("Invalid route.netmasl %s", route.Netmask)))
			return
		}
	}

	var conf openvpn.OvpnConfig

	if app.serverConf != nil {
		conf = *app.serverConf
		if serviceName != conf.ServiceName {
			returnErrorMessage(w, http.StatusBadRequest, errors.New("can't edit another instance"))
			return
		}
	} else {
		conf = *openvpn.InitServerConf()
		conf.ServiceName = serviceName
		log.Printf("conf: %v", conf)
	}

	if savePayload.ServerCertificate != nil && len(*savePayload.ServerCertificate) > 0 {
		commonName := *savePayload.ServerCertificate
		if !openvpn.IsValidServerCert(app.easyrsa, commonName) {
			returnErrorMessage(w, http.StatusBadRequest, errors.New("invalid server certificate"))
			return
		}
		// when creating new service, we can set the common name of the certificate
		conf.Cert = "easyrsa/pki/issued/" + commonName + ".crt"
		conf.Key = "easyrsa/pki/private/" + commonName + ".key"
		conf.MasterCn = commonName
	}

	// store in temporary object
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
	conf.RoutesPush = savePayload.RoutesPush
	conf.Auth = savePayload.Auth
	conf.EnableMtu = savePayload.EnableMtu
	conf.TunMtu = savePayload.TunMtu
	conf.DnsIpv4 = savePayload.DnsIpv4
	conf.DnsIpv6 = savePayload.DnsIpv6

	backupFile := fmt.Sprintf("%s.backup", *serverConfFile)
	initialServer := false
	if shell.FileExist(*serverConfFile) {
		// make a backup of the original OpenVPN config file
		err = shell.FileCopy(*serverConfFile, backupFile)
		if err != nil {
			returnErrorMessage(w, http.StatusBadRequest, errors.New("can't backup config file"))
			return
		}
	} else {
		log.Printf("initial server")
		initialServer = true
	}

	//log.Printf("ensure ccd dir exists")
	err = openvpn.CreateCcdIfNotExists(*serverConfFile, &conf)
	if err != nil {
		log.Printf("fail to create ccd dir %s", err)
	}

	// overwrite original config file
	err = shell.WriteFile(*serverConfFile, openvpn.BuildConfig(conf))
	if err != nil {
		shell.FileCopy(backupFile, *serverConfFile)
		returnErrorMessage(w, http.StatusBadRequest, err)
		return
	}

	err = app.restartServer("server")
	if err != nil {
		// rollback config and restart server on error
		if shell.FileExist(backupFile) {
			shell.FileCopy(backupFile, *serverConfFile)
			err = app.restartServer("server")
			shell.DeleteFile(backupFile)
		}
		// remove the config file if it fails to start for the first time
		if initialServer {
			shell.DeleteFile(*serverConfFile)
		}
		returnErrorMessage(w, http.StatusBadRequest, errors.New("fail to start service"))
		return
	}

	// store the working config in memory
	if app.serverConf == nil {
		app.serverConf = &conf
		// start management thread when it is the first time
		if len(app.serverConf.Management) > 0 {
			go app.connectToManagementInterface()
		}
	} else {
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
		app.serverConf.Routes = conf.Routes
		app.serverConf.RoutesPush = conf.RoutesPush
	}

	err = returnJson(w, app.exportServiceSettings())
	if err != nil {
		log.Printf("error sending response")
	}
}

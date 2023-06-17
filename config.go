package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"unicode"
)

type ConfigPublicSettings struct {
	Server                      string   `json:"server"`
	ForceGatewayIpv4            bool     `json:"forceGatewayIpv4"`
	ForceGatewayIpv4ExceptDhcp  bool     `json:"forceGatewayIpv4ExceptDhcp"`
	ForceGatewayIpv4ExceptDns   bool     `json:"forceGatewayIpv4ExceptDns"`
	ServerIpv6                  string   `json:"serverIpv6"`
	ForceGatewayIpv6            bool     `json:"forceGatewayIpv6"`
	ClientToClient              bool     `json:"clientToClient"`
	DuplicateCn                 bool     `json:"duplicateCn"`
	CompLzo                     bool     `json:"compLzo"`
	Auth                        string   `json:"auth"`
	EnableMtu                   bool     `json:"enableMtu"`
	TunMtu                      int      `json:"tunMtu"`
	Routes                      []Route  `json:"routes"`
	Pushs                       []Push   `json:"pushs"`
	PushRoutes                  []string `json:"pushRoutes"`
	DnsIpv4						string   `json:"dnsIpv4"`
	DnsIpv6						string   `json:"dnsIpv6"`
}

type ServerSavePayload struct {
	Server                      string   `json:"server"`
	ForceGatewayIpv4            bool     `json:"forceGatewayIpv4"`
	ForceGatewayIpv4ExceptDhcp  bool     `json:"forceGatewayIpv4ExceptDhcp"`
	ForceGatewayIpv4ExceptDns   bool     `json:"forceGatewayIpv4ExceptDns"`
	ServerIpv6                  string   `json:"serverIpv6"`
	ForceGatewayIpv6            bool     `json:"forceGatewayIpv6"`
	ClientToClient              bool     `json:"clientToClient"`
	DuplicateCn                 bool     `json:"duplicateCn"`
	CompLzo                     bool     `json:"compLzo"`
	Auth                        string   `json:"auth"`
	EnableMtu                   bool     `json:"enableMtu"`
	TunMtu                      int      `json:"tunMtu"`
	Routes                      []Route  `json:"routes"`
	DnsIpv4						string   `json:"dnsIpv4"`
	DnsIpv6						string   `json:"dnsIpv6"`
}


type ConfigPublicUser struct {
	Username     string `json:"username"`
	Name         string `json:"name"`
}

type ConfigPublicOpenvn struct {
	Url          string                   `json:"url"`
	Settings     *ConfigPublicSettings    `json:"settings,omitempty"`
	Preferences  *ConfigPublicPreferences `json:"preferences,omitempty"`
	Unconfigured *bool                    `json:"unconfigured,omitempty"`
}

type ConfigPublic struct {
	User         *ConfigPublicUser  `json:"user,omitempty"`
	Openvpn      ConfigPublicOpenvn `json:"openvpn"`
}

type Push struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Comment string `json:"comment"`
}

type OvpnConfig struct {
	server                     string   // 10.8.0.0 255.255.255.0
	forceGatewayIpv4           bool     // push "redirect-gateway def1 bypass-dhcp"
	forceGatewayIpv4ExceptDhcp bool     // push "redirect-gateway def1 bypass-dhcp"
	forceGatewayIpv4ExceptDns  bool     // push "redirect-gateway def1 bypass-dns"
	port                       int      // 1194
	proto                      string   // udp udp6
	dev                        string   // tun tap
	enableMtu                  bool     // tru/false
	tunMtu                     int      // 60000
	dnsIpv4                    string   // 10.8.0.1
	dnsIpv6                    string   // fd42:42:42:42::1
	fragment                   int      // 0
	user                       string   // nobody
	group                      string   // nogroup
	mssfix                     int      // 0
	management                 string   // localhost 7505
	ca                         string   // ca.crt
	cert                       string   // server.crt
	key                        string   // server.key
	dh                         string   // dh2048.pem none
	ifconfigPoolPersist        string   // ipp.txt
	keepalive                  string   // 10 120
	compLzo                    bool
	allowCompression           bool
	persistKey                 bool
	persistTun                 bool
	status                     string   // /var/log/openvpn/status.log
	verb                       int      // 1 3
	clientConfigDir            string   // ccd
	clientToClient             bool
	duplicateCn                bool
	topology                   string   // subnet
	serverIpv6                 string   // fd42:42:42:42::/112
	forceGatewayIpv6           bool     // push "redirect-gateway ipv6"
	tunIpv6                    bool
	ecdhCurve                  string   // prime256v1
	tlsCrypt                   string   // tls-crypt.key
	crlVerify                  string   // crl.pem
	auth                       string   // SHA256
	cipher                     string   // AES-128-GCM
	ncpCiphers                 string   // AES-128-GCM
	tlsServer                  bool
	tlsVersionMin              string   // 1.2
	tlsCipher                  string   // TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
	log                        string   // /var/log/openvpn.log
	routes                     []Route  // 10.42.44.0 255.255.255.0
	                                    // 10.42.78.0 255.255.255.0
	                                    // 10.8.0.0 255.255.255.0
	push                       []Push   // "dhcp-option DNS 10.8.0.1"
	                                    // "dhcp-option DNS fd42:42:42:42::1"
	                                    // "redirect-gateway def1 bypass-dhcp"
	                                    // "tun-ipv6"
	                                    // "routes-ipv6 2000::/3"
	                                    // "redirect-gateway ipv6"
}

func (app *OvpnAdmin) exportPublicSettings() *ConfigPublicSettings {
	var settings = new(ConfigPublicSettings)
	settings.Server = convertNetworkMaskCidr(app.serverConf.server)
	settings.ForceGatewayIpv4 = app.serverConf.forceGatewayIpv4
	settings.ForceGatewayIpv4ExceptDhcp = app.serverConf.forceGatewayIpv4ExceptDhcp
	settings.ForceGatewayIpv4ExceptDns = app.serverConf.forceGatewayIpv4ExceptDns
	settings.ServerIpv6 = app.serverConf.serverIpv6
	settings.ForceGatewayIpv6 = app.serverConf.forceGatewayIpv6
	settings.DuplicateCn = app.serverConf.duplicateCn
	settings.ClientToClient = app.serverConf.clientToClient
	settings.CompLzo = app.serverConf.compLzo
	settings.Routes = app.serverConf.routes
	settings.Auth = app.serverConf.auth
	settings.Pushs = app.serverConf.push
	settings.EnableMtu = app.serverConf.enableMtu
	settings.TunMtu = app.serverConf.tunMtu
	settings.DnsIpv4 = app.serverConf.dnsIpv4
	settings.DnsIpv6 = app.serverConf.dnsIpv6
	//settings.Routes = make([]string, 0)
	//for _, routes := range app.serverConf.routes {
	//	settings.Routes = append(settings.Routes, convertNetworkMaskCidr(routes))
	//}
	return settings
}

func (app *OvpnAdmin) showConfig(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	configPublic := new(ConfigPublic)
	configPublic.Openvpn.Url = ""

	auth := getAuthCookie(r)
	ok, jwtUsername := app.jwtUsername(auth)
	if ok {
		configPublic.User = app.getUserProfile(jwtUsername)
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

func (app *OvpnAdmin) getUserProfile(username string) *ConfigPublicUser {
	for _, u := range app.applicationPreferences.Users {
		if u.Username == username {
			configPublicUser := new(ConfigPublicUser)
			configPublicUser.Username = username
			configPublicUser.Name = u.Name
			return configPublicUser
		}
	}
	return nil
}

func (app *OvpnAdmin) parseServerConf(file string) {
	lines := strings.Split(fRead(file), "\n")

	app.serverConf.tunMtu = -1
	app.serverConf.fragment = -1
	app.serverConf.mssfix = -1
	for _, line := range lines {
		line = strings.TrimLeft(line, " ")
		if len(line) == 0 {
			continue
		}
		if line[0:1] == "#" {
			line = strings.TrimLeft(line, "# ")
			parseServerConfLine(&app.serverConf, line, true)
		} else {
			parseServerConfLine(&app.serverConf, line, false)
		}
	}

	log.Printf("config %v", app.serverConf)
}

func parseServerConfLine(serverConf *OvpnConfig, line string, commented bool) {
	key, value := getKeyValue(line)

	switch {
	case key == "server":
		serverConf.server = getValueWithoutComment(line)
	case key == "port":
		if n, err := getIntValueWithoutComment(line); err == nil {
			serverConf.port = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "proto":
		serverConf.proto = getValueWithoutComment(line)
	case key == "dev":
		serverConf.dev = getValueWithoutComment(line)
	case key == "tun-mtu":
		if n, err := getIntValueWithoutComment(line); err == nil {
			serverConf.enableMtu = true
			serverConf.tunMtu = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "fragment":
		if n, err := getIntValueWithoutComment(line); err == nil {
			serverConf.fragment = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "user":
		serverConf.user = getValueWithoutComment(line)
	case key == "group":
		serverConf.group = getValueWithoutComment(line)
	case key == "mssfix":
		if n, err := getIntValueWithoutComment(line); err == nil {
			serverConf.mssfix = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "management":
		serverConf.management = getValueWithoutComment(line)
	case key == "ca":
		serverConf.ca = getValueWithoutComment(line)
	case key == "cert":
		serverConf.cert = getValueWithoutComment(line)
	case key == "key":
		serverConf.key = getValueWithoutComment(line)
	case key == "dh":
		serverConf.dh = getValueWithoutComment(line)
	case key == "ifconfig-pool-persist":
		serverConf.ifconfigPoolPersist = getValueWithoutComment(line)
	case key == "keepalive":
		serverConf.keepalive = getValueWithoutComment(line)
	case key == "comp-lzo":
		serverConf.compLzo = true
	case key == "allow-compression":
		serverConf.allowCompression = true
	case key == "persist-key":
		serverConf.persistKey = true
	case key == "persist-tun":
		serverConf.persistTun = true
	case key == "status":
		serverConf.status = getValueWithoutComment(line)
	case key == "verb":
		if n, err := getIntValueWithoutComment(line); err == nil {
			serverConf.verb = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "client-config-dir":
		serverConf.clientConfigDir = getValueWithoutComment(line)
	case key == "client-to-client":
		serverConf.clientToClient = true
	case key == "duplicate-cn":
		serverConf.duplicateCn = true
	case key == "topology":
		serverConf.topology = getValueWithoutComment(line)
	case key == "server-ipv6":
		serverConf.serverIpv6 = getValueWithoutComment(line)
	case key == "tun-ipv6":
		serverConf.tunIpv6 = true
	case key == "ecdh-curve":
		serverConf.ecdhCurve = getValueWithoutComment(line)
	case key == "tls-crypt":
		serverConf.tlsCrypt = getValueWithoutComment(line)
	case key == "crl-verify":
		serverConf.crlVerify = getValueWithoutComment(line)
	case key == "auth":
		serverConf.auth = getValueWithoutComment(line)
	case key == "cipher":
		serverConf.cipher = getValueWithoutComment(line)
	case key == "ncp-ciphers":
		serverConf.ncpCiphers = getValueWithoutComment(line)
	case key == "tls-server":
		serverConf.tlsServer = true
	case key == "tls-version-min":
		serverConf.tlsVersionMin = getValueWithoutComment(line)
	case key == "tls-cipher":
		serverConf.tlsCipher = getValueWithoutComment(line)
	case key == "log":
		serverConf.log = getValueWithoutComment(line)
	case key == "route":
		if route, err := getRouteValueWithComment(line); err == nil {
			serverConf.routes = append(serverConf.routes, route)
		} else {
			log.Printf("failed to line %v\n", err)
		}
	case key == "push":
		value, comment := getQuotedValueAndComment(value)
		log.Printf("parsed [%d] [%s] [%s]", commented, value, comment)
		//getQuotedValueWithoutComment(line)
		extractPushConfig(serverConf, !commented, value, comment)

	default:
		log.Printf("skipped '%s'", line)
	}
}

func extractPushConfig(serverConf *OvpnConfig, enabled bool, line string, comment string) {
	if !enabled {
		return
	}
	parts := strings.Split(line, " ")

	if parts[0] == "redirect-gateway" {
		parts = parts[1:]
		for _, part := range parts {
			if part == "def1" {
				serverConf.forceGatewayIpv4 = true
			} else if part == "ipv6" {
				serverConf.forceGatewayIpv6 = true
			} else if part == "bypass-dhcp" {
				serverConf.forceGatewayIpv4ExceptDhcp = true
			} else if part == "bypass-dns" {
				serverConf.forceGatewayIpv4ExceptDns = true
			} else {
				log.Printf("Unrecognized redirect-gateway option '%s'", part)
			}
		}
	} else if parts[0] == "dhcp-option" && parts[1] == "DNS" {
		if isIpv4(parts[2]) {
			serverConf.dnsIpv4 = parts[2]
		} else {
			serverConf.dnsIpv6 = parts[2]
		}
	} else {
		log.Printf("import push '%v'", parts)

		// TODO: extract:
		//   - #push "dhcp-option DNS 10.8.0.1"
		//   - #push "tun-ipv6"
		//   - #push "route-ipv6 2000::/3"
		//   - #push "dhcp-option DNS fd42:42:42:42::1"
		// should be grouped by purpose:
		//   ipv4:
		//     - dhcp-option DNS 10.8.0.1
		//     - routes
		//   ipv6:
		//     - tun-ipv6
		//     - redirect-gateway ipv6
		//     - route-ipv6 2000::/3
		//     - dhcp-option DNS fd42:42:42:42::1
		//     - routes
		//
		serverConf.push = append(serverConf.push, Push{Enabled: enabled, Name:parts[0], Value: line, Comment: comment})
	}
}

func (app *OvpnAdmin) writeConfig(file string, config OvpnConfig) (string, error) {
	var lines = make([]string, 0)

	if len(config.server) > 0 {
		lines = append(lines, fmt.Sprintf("server %s", config.server))
	}
	if config.port != 0 {
		lines = append(lines, fmt.Sprintf("port %d", config.port))
	}
	if len(config.proto) > 0 {
		lines = append(lines, fmt.Sprintf("proto %s", config.proto))
	}
	if len(config.dev) > 0 {
		lines = append(lines, fmt.Sprintf("dev %s", config.dev))
	}
	if config.enableMtu && config.tunMtu >= 0 {
		lines = append(lines, fmt.Sprintf("tun-mtu %d", config.tunMtu))
	}
	if config.fragment >= 0 {
		lines = append(lines, fmt.Sprintf("fragment %d", config.fragment))
	}
	if len(config.user) > 0 {
		lines = append(lines, fmt.Sprintf("user %s", config.user))
	}
	if len(config.group) > 0 {
		lines = append(lines, fmt.Sprintf("group %s", config.group))
	}
	if config.mssfix >= 0 {
		lines = append(lines, fmt.Sprintf("mssfix %d", config.mssfix))
	}
	if len(config.management) > 0 {
		lines = append(lines, fmt.Sprintf("management %s", config.management))
	}
	if len(config.ca) > 0 {
		lines = append(lines, fmt.Sprintf("ca %s", config.ca))
	}
	if len(config.cert) > 0 {
		lines = append(lines, fmt.Sprintf("cert %s", config.cert))
	}
	if len(config.key) > 0 {
		lines = append(lines, fmt.Sprintf("key %s", config.key))
	}
	if len(config.dh) > 0 {
		lines = append(lines, fmt.Sprintf("dh %s", config.dh))
	}
	if len(config.ifconfigPoolPersist) > 0 {
		lines = append(lines, fmt.Sprintf("ifconfig-pool-persist %s", config.ifconfigPoolPersist))
	}
	if len(config.keepalive) > 0 {
		lines = append(lines, fmt.Sprintf("keepalive %s", config.keepalive))
	}
	if config.compLzo {
		lines = append(lines, fmt.Sprintf("comp-lzo"))
	}
	if config.allowCompression {
		lines = append(lines, fmt.Sprintf("allow-compression yes"))
	}
	if config.persistKey {
		lines = append(lines, fmt.Sprintf("persist-key"))
	}
	if config.persistTun {
		lines = append(lines, fmt.Sprintf("persist-tun"))
	}
	if len(config.status) > 0 {
		lines = append(lines, fmt.Sprintf("status %s", config.status))
	}
	if config.verb >= 0 {
		lines = append(lines, fmt.Sprintf("verb %d", config.verb))
	}
	if len(config.clientConfigDir) > 0 {
		lines = append(lines, fmt.Sprintf("client-config-dir %s", config.clientConfigDir))
	}
	if config.clientToClient {
		lines = append(lines, fmt.Sprintf("client-to-client"))
	}
	if config.duplicateCn {
		lines = append(lines, fmt.Sprintf("duplicate-cn"))
	}
	if len(config.topology) > 0 {
		lines = append(lines, fmt.Sprintf("topology %s", config.topology))
	}
	if len(config.serverIpv6) > 0 {
		lines = append(lines, fmt.Sprintf("server-ipv6 %s", config.serverIpv6))
		if config.tunIpv6 {
			// tun-ipv6 is for old clients
			lines = append(lines, fmt.Sprintf("tun-ipv6"))
		}
	}

	if len(config.ecdhCurve) > 0 {
		lines = append(lines, fmt.Sprintf("ecdh-curve %s", config.ecdhCurve))
	}
	if len(config.tlsCrypt) > 0 {
		lines = append(lines, fmt.Sprintf("tls-crypt %s", config.tlsCrypt))
	}
	if len(config.crlVerify) > 0 {
		lines = append(lines, fmt.Sprintf("crl-verify %s", config.crlVerify))
	}
	if len(config.auth) > 0 {
		lines = append(lines, fmt.Sprintf("auth %s", config.auth))
	}
	if len(config.cipher) > 0 {
		lines = append(lines, fmt.Sprintf("cipher %s", config.cipher))
	}
	if len(config.ncpCiphers) > 0 {
		lines = append(lines, fmt.Sprintf("ncp-ciphers %s", config.ncpCiphers))
	}
	if config.tlsServer {
		lines = append(lines, fmt.Sprintf("tls-server"))
	}
	if len(config.tlsVersionMin) > 0 {
		lines = append(lines, fmt.Sprintf("tls-version-min %s", config.tlsVersionMin))
	}
	if len(config.tlsCipher) > 0 {
		lines = append(lines, fmt.Sprintf("tls-cipher %s", config.tlsCipher))
	}
	if len(config.log) > 0 {
		lines = append(lines, fmt.Sprintf("log %s", config.log))
	}
	if len(config.routes) > 0 {
		lines = append(lines, "")
		for _, route := range config.routes {
			lines = append(lines, formatRoute(route))
		}
	}
	if config.forceGatewayIpv4 {
		options := ""
		if config.forceGatewayIpv4ExceptDhcp {
			options = options + " bypass-dhcp"
		}
		if config.forceGatewayIpv4ExceptDns {
			options = options + " bypass-dns"
		}
		lines = append(lines, fmt.Sprintf("push \"redirect-gateway def1%s\"", options))
	}
	if config.forceGatewayIpv6 {
		lines = append(lines, "push \"redirect-gateway ipv6\"")
	}
	if len(config.dnsIpv4) > 0 {
		lines = append(lines, fmt.Sprintf("push \"dhcp-option DNS %s\"", config.dnsIpv4))
	}
	if len(config.dnsIpv6) > 0 {
		lines = append(lines, fmt.Sprintf("push \"dhcp-option DNS %s\"", config.dnsIpv6))
	}
	if len(config.push) > 0 {
		lines = append(lines, "")
		for _, s := range config.push {
			lines = append(lines, formatPush(s))
		}
	}
	lines = append(lines, "")
	err := fWrite(file, strings.Join(lines, "\n"))
	if err != nil {
		return "Can't write file", err
	}
	return "", nil
}

func formatPush(push Push) string {
	var line = ""
	if !push.Enabled {
		line += "# "
	}
	line += "push \"" + strings.Replace(push.Value, "\"", "\\\"", -1) + "\""
	if len(push.Comment) > 0 {
		line += " ## "+push.Comment
	}
	return line
}

func formatRoute(route Route) string {
	var parts = make([]string, 0)
	parts = append(parts, "route")
	parts = append(parts, route.Address)
	parts = append(parts, route.Netmask)
	if len(route.Description) > 0 {
		parts = append(parts, "#")
		parts = append(parts, route.Description)
	}
	return strings.Join(parts, " ")
}

func getKeyValue(line string) (string, string) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) > 1 {
		return parts[0], strings.TrimLeft(parts[1], " ")
	}
	return parts[0], ""
}

func getQuotedValue(line string) string {
	line = strings.TrimPrefix(strings.TrimSuffix(line, "\""), "\"")
	line = strings.ReplaceAll(line, "\\\"", "\"")
	return line
}

func getValueWithoutComment(line string) string {
	if p := strings.Index(line, "#"); p >= 0 {
		line = line[0:p]
	}
	line = strings.TrimRightFunc(line, unicode.IsSpace)
	if p := strings.Index(line, " "); p >= 0 {
		line = line[p+1:len(line)]
	}
	return line
}

func getQuotedValueAndComment(line string) (string, string) {
	var comment = ""
	if p := strings.Index(line, "#"); p >= 0 {
		comment = strings.TrimLeft(line[p+1:], "# ")
		line = strings.TrimRight(line[:p], " ")
	} else {
		line = strings.TrimRight(line, " ")
	}
	return getQuotedValue(line), comment
}

func getRouteValueWithComment(line string) (Route, error) {
	var comment = ""
	if p := strings.Index(line, "#"); p >= 0 {
		comment = strings.TrimSpace(line[p+1:])
		line = line[0:p]
	}
	line = strings.TrimRightFunc(line, unicode.IsSpace)
	if p := strings.Index(line, " "); p >= 0 {
		line = line[p+1:len(line)]
	}

	var route Route
	route.Description = comment
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return route, errors.New("Invalid route format")
	}
	route.Address = parts[0]
	route.Netmask = parts[1]
	return route, nil
}

func getIntValueWithoutComment(line string) (int, error) {
	if p := strings.Index(line, "#"); p >= 0 {
		line = line[0:p]
	}
	key := line
	value := ""
	if p := strings.Index(line, " "); p >= 0 {
		key = line[0:p]
		value = line[p+1:len(line)]
	}
	if n, err := strconv.Atoi(value); err == nil {
		return n, nil
	} else {
		log.Printf("error: %s '%s' is not an integer", key, value)
		return -1, err
	}
}
func (app *OvpnAdmin) postServerConfig(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
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
	conf.server = convertCidrNetworkMask(savePayload.Server)
	conf.forceGatewayIpv4 = savePayload.ForceGatewayIpv4
	conf.forceGatewayIpv4ExceptDhcp = savePayload.ForceGatewayIpv4ExceptDhcp
	conf.forceGatewayIpv4ExceptDns = savePayload.ForceGatewayIpv4ExceptDns
	conf.serverIpv6 = savePayload.ServerIpv6
	conf.forceGatewayIpv6 = savePayload.ForceGatewayIpv6
	conf.compLzo = savePayload.CompLzo
	conf.clientToClient = savePayload.ClientToClient
	conf.duplicateCn = savePayload.DuplicateCn
	conf.routes = savePayload.Routes
	conf.auth = savePayload.Auth
	conf.enableMtu = savePayload.EnableMtu
	conf.tunMtu = savePayload.TunMtu
	conf.dnsIpv4 = savePayload.DnsIpv4
	conf.dnsIpv6 = savePayload.DnsIpv6

	backupFile := fmt.Sprintf("%s.backup", *serverConfFile)

	// make a backup of the original OpenVPN config file
	err = fCopy(*serverConfFile, backupFile)
	if err != nil {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Can't backup config file"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	// write a temporary config file over the original one
	status, err := app.writeConfig(*serverConfFile, conf)
	if err != nil {
		fCopy(backupFile, *serverConfFile)
		jsonRaw, _ := json.Marshal(MessagePayload{Message: status})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	err = app.restartServer()
	if err != nil {
		// rollback config and restart server on error
		fCopy(backupFile, *serverConfFile)
		err = app.restartServer()
		jsonRaw, _ := json.Marshal(MessagePayload{Message: status})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	// store the working config in memory
	app.serverConf.server = conf.server
	app.serverConf.forceGatewayIpv4 = conf.forceGatewayIpv4
	app.serverConf.forceGatewayIpv4ExceptDhcp = conf.forceGatewayIpv4ExceptDhcp
	app.serverConf.forceGatewayIpv4ExceptDns = conf.forceGatewayIpv4ExceptDns
	app.serverConf.serverIpv6 = conf.serverIpv6
	app.serverConf.forceGatewayIpv6 = conf.forceGatewayIpv6
	app.serverConf.compLzo = conf.compLzo
	app.serverConf.clientToClient = conf.clientToClient
	app.serverConf.duplicateCn = conf.duplicateCn
	app.serverConf.auth = conf.auth
	app.serverConf.enableMtu = conf.enableMtu
	app.serverConf.tunMtu = conf.tunMtu
	app.serverConf.dnsIpv4 = conf.dnsIpv4
	app.serverConf.dnsIpv6 = conf.dnsIpv6

	w.WriteHeader(http.StatusNoContent)
}

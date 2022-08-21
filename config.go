package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	log "github.com/sirupsen/logrus"
	"unicode"
)

func (oAdmin *OvpnAdmin) parseServerConf(file string) {
	lines := strings.Split(fRead(file), "\n")

	oAdmin.serverConf.tunMtu = -1
	oAdmin.serverConf.fragment = -1
	oAdmin.serverConf.mssfix = -1
	for _, line := range lines {
		if len(line) == 0 || line[0:1] == "#" {
			continue
		}
		key := extractKey(line)
		switch {
		case key == "server":
			oAdmin.serverConf.server = getValueWithoutComment(line)
		case key == "port":
			if n, err := getIntValueWithoutComment(line); err == nil {
				oAdmin.serverConf.port = n
			}
		case key == "proto":
			oAdmin.serverConf.proto = getValueWithoutComment(line)
		case key == "dev":
			oAdmin.serverConf.dev = getValueWithoutComment(line)
		case key == "tun-mtu":
			if n, err := getIntValueWithoutComment(line); err == nil {
				oAdmin.serverConf.tunMtu = n
			}
		case key == "fragment":
			if n, err := getIntValueWithoutComment(line); err == nil {
				oAdmin.serverConf.fragment = n
			}
		case key == "user":
			oAdmin.serverConf.user = getValueWithoutComment(line)
		case key == "group":
			oAdmin.serverConf.group = getValueWithoutComment(line)
		case key == "mssfix":
			if n, err := getIntValueWithoutComment(line); err == nil {
				oAdmin.serverConf.mssfix = n
			}
		case key == "management":
			oAdmin.serverConf.management = getValueWithoutComment(line)
		case key == "ca":
			oAdmin.serverConf.ca = getValueWithoutComment(line)
		case key == "cert":
			oAdmin.serverConf.cert = getValueWithoutComment(line)
		case key == "key":
			oAdmin.serverConf.key = getValueWithoutComment(line)
		case key == "dh":
			oAdmin.serverConf.dh = getValueWithoutComment(line)
		case key == "ifconfig-pool-persist":
			oAdmin.serverConf.ifconfigPoolPersist = getValueWithoutComment(line)
		case key == "keepalive":
			oAdmin.serverConf.keepalive = getValueWithoutComment(line)
		case key == "comp-lzo":
			oAdmin.serverConf.compLzo = true
		case key == "allow-compression":
			oAdmin.serverConf.allowCompression = true
		case key == "persist-key":
			oAdmin.serverConf.persistKey = true
		case key == "persist-tun":
			oAdmin.serverConf.persistTun = true
		case key == "status":
			oAdmin.serverConf.status = getValueWithoutComment(line)
		case key == "verb":
			if n, err := getIntValueWithoutComment(line); err == nil {
				oAdmin.serverConf.verb = n
			}
		case key == "client-config-dir":
			oAdmin.serverConf.clientConfigDir = getValueWithoutComment(line)
		case key == "client-to-client":
			oAdmin.serverConf.clientToClient = true
		case key == "duplicate-cn":
			oAdmin.serverConf.duplicateCn = true
		case key == "topology":
			oAdmin.serverConf.topology = getValueWithoutComment(line)
		case key == "server-ipv6":
			oAdmin.serverConf.serverIpv6 = getValueWithoutComment(line)
		case key == "tun-ipv6":
			oAdmin.serverConf.tunIpv6 = true
		case key == "ecdh-curve":
			oAdmin.serverConf.ecdhCurve = getValueWithoutComment(line)
		case key == "tls-crypt":
			oAdmin.serverConf.tlsCrypt = getValueWithoutComment(line)
		case key == "crl-verify":
			oAdmin.serverConf.crlVerify = getValueWithoutComment(line)
		case key == "auth":
			oAdmin.serverConf.auth = getValueWithoutComment(line)
		case key == "cipher":
			oAdmin.serverConf.cipher = getValueWithoutComment(line)
		case key == "ncp-ciphers":
			oAdmin.serverConf.ncpCiphers = getValueWithoutComment(line)
		case key == "tls-server":
			oAdmin.serverConf.tlsServer = true
		case key == "tls-version-min":
			oAdmin.serverConf.tlsVersionMin = getValueWithoutComment(line)
		case key == "tls-cipher":
			oAdmin.serverConf.tlsCipher = getValueWithoutComment(line)
		case key == "log":
			oAdmin.serverConf.log = getValueWithoutComment(line)
		case key == "route":
			oAdmin.serverConf.route = append(oAdmin.serverConf.route, getQuotedValueWithoutComment(line))
		case key == "push":
			oAdmin.serverConf.push = append(oAdmin.serverConf.push, getQuotedValueWithoutComment(line))
		default:
			log.Printf("skipped '%s'", line)
		}
	}

	log.Printf("config %v", oAdmin.serverConf)
}

func (oAdmin *OvpnAdmin) writeConfig(file string, config OvpnConfig) (string, error) {
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
	if config.tunMtu >= 0 {
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
	}
	if config.tunIpv6 {
		lines = append(lines, fmt.Sprintf("tun-ipv6"))
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
	if len(config.route) > 0 {
		lines = append(lines, "")
		for _, s := range config.route {
			lines = append(lines, fmt.Sprintf("route %s", s))
		}
	}
	if len(config.push) > 0 {
		lines = append(lines, "")
		for _, s := range config.push {
			lines = append(lines, fmt.Sprintf("push \"%s\"", s))
		}
	}
	lines = append(lines, "")
	err := fWrite(file, strings.Join(lines, "\n"))
	if err != nil {
		return "Can't write file", err
	}
	return "", nil
}

func extractKey(line string) string {
	return strings.Fields(line)[0]
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

func getQuotedValueWithoutComment(line string) string {
	line = getValueWithoutComment(line)
	line = strings.TrimPrefix(strings.TrimSuffix(line, "\""), "\"")
	return line
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

func (oAdmin *OvpnAdmin) saveConfig(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
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
		log.Errorln(err)
	}

	conf := oAdmin.serverConf
	conf.server = convertCidrNetworkMask(savePayload.Server)
	conf.serverIpv6 = savePayload.ServerIpv6
	conf.compLzo = savePayload.CompLzo
	conf.duplicateCn = savePayload.DuplicateCn


	backupFile := fmt.Sprintf("%s.backup", *serverConfFile)

	err = fCopy(*serverConfFile, backupFile)
	if err != nil {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Can't backup config file"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	status, err := oAdmin.writeConfig(*serverConfFile, conf)
	if err != nil {
		fCopy(backupFile, *serverConfFile)
		jsonRaw, _ := json.Marshal(MessagePayload{Message: status})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	err = oAdmin.restartServer()
	if err != nil {
		fCopy(backupFile, *serverConfFile)
		jsonRaw, _ := json.Marshal(MessagePayload{Message: status})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

	oAdmin.serverConf.server = conf.server
	oAdmin.serverConf.serverIpv6 = conf.serverIpv6
	oAdmin.serverConf.compLzo = conf.compLzo
	oAdmin.serverConf.duplicateCn = conf.duplicateCn

	w.WriteHeader(http.StatusNoContent)
}

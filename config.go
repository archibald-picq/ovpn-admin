package main

import (
	"fmt"
	"strconv"
	"strings"
	log "github.com/sirupsen/logrus"
	"unicode"
)

func (oAdmin *OvpnAdmin) parseServerConf(file string) {
	lines := strings.Split(fRead(file), "\n")

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

func (oAdmin *OvpnAdmin) writeConfig(file string) {
	var lines = make([]string, 0)

	if len(oAdmin.serverConf.server) > 0 {
		lines = append(lines, fmt.Sprintf("server %s", oAdmin.serverConf.server))
	}
	if oAdmin.serverConf.port != 0 {
		lines = append(lines, fmt.Sprintf("port %d", oAdmin.serverConf.port))
	}
	if len(oAdmin.serverConf.proto) > 0 {
		lines = append(lines, fmt.Sprintf("proto %s", oAdmin.serverConf.proto))
	}
	if len(oAdmin.serverConf.dev) > 0 {
		lines = append(lines, fmt.Sprintf("dev %s", oAdmin.serverConf.dev))
	}
	if oAdmin.serverConf.tunMtu >= 0 {
		lines = append(lines, fmt.Sprintf("tun-mtu %d", oAdmin.serverConf.tunMtu))
	}
	if oAdmin.serverConf.fragment >= 0 {
		lines = append(lines, fmt.Sprintf("fragment %d", oAdmin.serverConf.fragment))
	}
	if len(oAdmin.serverConf.user) > 0 {
		lines = append(lines, fmt.Sprintf("user %s", oAdmin.serverConf.user))
	}
	if len(oAdmin.serverConf.group) > 0 {
		lines = append(lines, fmt.Sprintf("group %s", oAdmin.serverConf.group))
	}
	if oAdmin.serverConf.mssfix >= 0 {
		lines = append(lines, fmt.Sprintf("mssfix %d", oAdmin.serverConf.mssfix))
	}
	if len(oAdmin.serverConf.management) > 0 {
		lines = append(lines, fmt.Sprintf("management %s", oAdmin.serverConf.management))
	}
	if len(oAdmin.serverConf.ca) > 0 {
		lines = append(lines, fmt.Sprintf("ca %s", oAdmin.serverConf.ca))
	}
	if len(oAdmin.serverConf.cert) > 0 {
		lines = append(lines, fmt.Sprintf("cert %s", oAdmin.serverConf.cert))
	}
	if len(oAdmin.serverConf.key) > 0 {
		lines = append(lines, fmt.Sprintf("key %s", oAdmin.serverConf.key))
	}
	if len(oAdmin.serverConf.dh) > 0 {
		lines = append(lines, fmt.Sprintf("dh %s", oAdmin.serverConf.dh))
	}
	if len(oAdmin.serverConf.ifconfigPoolPersist) > 0 {
		lines = append(lines, fmt.Sprintf("ifconfig-pool-persist %s", oAdmin.serverConf.ifconfigPoolPersist))
	}
	if len(oAdmin.serverConf.keepalive) > 0 {
		lines = append(lines, fmt.Sprintf("keepalive %s", oAdmin.serverConf.keepalive))
	}
	if oAdmin.serverConf.compLzo {
		lines = append(lines, fmt.Sprintf("comp-lzo"))
	}
	if oAdmin.serverConf.persistKey {
		lines = append(lines, fmt.Sprintf("persist-key"))
	}
	if oAdmin.serverConf.persistTun {
		lines = append(lines, fmt.Sprintf("persist-tun"))
	}
	if len(oAdmin.serverConf.status) > 0 {
		lines = append(lines, fmt.Sprintf("status %s", oAdmin.serverConf.status))
	}
	if oAdmin.serverConf.verb >= 0 {
		lines = append(lines, fmt.Sprintf("verb %d", oAdmin.serverConf.verb))
	}
	if len(oAdmin.serverConf.clientConfigDir) > 0 {
		lines = append(lines, fmt.Sprintf("client-config-dir %s", oAdmin.serverConf.clientConfigDir))
	}
	if oAdmin.serverConf.clientToClient {
		lines = append(lines, fmt.Sprintf("client-to-client"))
	}
	if oAdmin.serverConf.duplicateCn {
		lines = append(lines, fmt.Sprintf("duplicate-cn"))
	}
	if len(oAdmin.serverConf.topology) > 0 {
		lines = append(lines, fmt.Sprintf("topology %s", oAdmin.serverConf.topology))
	}
	if len(oAdmin.serverConf.serverIpv6) > 0 {
		lines = append(lines, fmt.Sprintf("server-ipv6 %s", oAdmin.serverConf.serverIpv6))
	}
	if oAdmin.serverConf.tunIpv6 {
		lines = append(lines, fmt.Sprintf("tun-ipv6"))
	}
	if len(oAdmin.serverConf.ecdhCurve) > 0 {
		lines = append(lines, fmt.Sprintf("ecdh-curve %s", oAdmin.serverConf.ecdhCurve))
	}
	if len(oAdmin.serverConf.tlsCrypt) > 0 {
		lines = append(lines, fmt.Sprintf("tls-crypt %s", oAdmin.serverConf.tlsCrypt))
	}
	if len(oAdmin.serverConf.crlVerify) > 0 {
		lines = append(lines, fmt.Sprintf("crl-verify %s", oAdmin.serverConf.crlVerify))
	}
	if len(oAdmin.serverConf.auth) > 0 {
		lines = append(lines, fmt.Sprintf("auth %s", oAdmin.serverConf.auth))
	}
	if len(oAdmin.serverConf.cipher) > 0 {
		lines = append(lines, fmt.Sprintf("cipher %s", oAdmin.serverConf.cipher))
	}
	if len(oAdmin.serverConf.ncpCiphers) > 0 {
		lines = append(lines, fmt.Sprintf("ncp-ciphers %s", oAdmin.serverConf.ncpCiphers))
	}
	if oAdmin.serverConf.tlsServer {
		lines = append(lines, fmt.Sprintf("tls-server"))
	}
	if len(oAdmin.serverConf.tlsVersionMin) > 0 {
		lines = append(lines, fmt.Sprintf("tls-version-min %s", oAdmin.serverConf.tlsVersionMin))
	}
	if len(oAdmin.serverConf.tlsCipher) > 0 {
		lines = append(lines, fmt.Sprintf("tls-cipher %s", oAdmin.serverConf.tlsCipher))
	}
	if len(oAdmin.serverConf.log) > 0 {
		lines = append(lines, fmt.Sprintf("log %s", oAdmin.serverConf.log))
	}
	if len(oAdmin.serverConf.route) > 0 {
		lines = append(lines, "")
		for _, s := range oAdmin.serverConf.route {
			lines = append(lines, fmt.Sprintf("route %s", s))
		}
	}
	if len(oAdmin.serverConf.push) > 0 {
		lines = append(lines, "")
		for _, s := range oAdmin.serverConf.push {
			lines = append(lines, fmt.Sprintf("push \"%s\"", s))
		}
	}
	lines = append(lines, "")
	err := fWrite(file, strings.Join(lines, "\n"))
	if err != nil {
		log.Error(err)
	}
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

func absolutizePath(referencePath string, relativePath string) string {
	if strings.HasPrefix(relativePath, "/") {
		return relativePath
	}
	relativePath = strings.TrimPrefix(relativePath, "./")

	if strings.HasSuffix("/", referencePath) {
		log.Printf("referencePath ends with '/': '%s' .. '%s'", referencePath, relativePath)
		return referencePath+relativePath;
	}
	p := strings.LastIndex(referencePath, "/")
	referencePath = referencePath[0:p+1]
	log.Printf("concat paths: '%s' .. '%s'", referencePath, relativePath)
	return referencePath+relativePath
}

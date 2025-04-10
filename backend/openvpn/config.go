package openvpn

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"rpiadm/backend/shell"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Push struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Comment string `json:"comment"`
}

type OvpnConfig struct {
	SourceFile                 string
	ServiceName                string
	Server                     string // 10.8.0.0 255.255.255.0
	MasterCn                   string
	ServerCert                 *IssuedCertificate
	ForceGatewayIpv4           bool    // push "redirect-gateway def1 bypass-dhcp"
	ForceGatewayIpv4ExceptDhcp bool    // push "redirect-gateway def1 bypass-dhcp"
	ForceGatewayIpv4ExceptDns  bool    // push "redirect-gateway def1 bypass-dns"
	Port                       int     // 1194
	proto                      string  // udp udp6
	dev                        string  // tun tap
	EnableMtu                  bool    // tru/false
	TunMtu                     int     // 60000
	DnsIpv4                    *string // 10.8.0.1
	DnsIpv6                    *string // fd42:42:42:42::1
	Fragment                   int     // 0
	user                       string  // nobody
	group                      string  // nogroup
	Mssfix                     int     // 0
	Management                 string  // localhost 7505
	ca                         string  // ca.crt
	caCert                     *IssuedCertificate
	Cert                       string // Server.crt
	Key                        string // Server.key
	dh                         string // dh2048.pem none
	ifconfigPoolPersist        string // ipp.txt
	keepalive                  string // 10 120
	CompLzo                    bool
	allowCompression           bool
	persistKey                 bool
	persistTun                 bool
	status                     string // /var/log/openvpn/status.log
	verb                       int    // 1 3
	ClientConfigDir            string // ccd
	ClientToClient             bool
	DuplicateCn                bool
	topology                   string  // subnet
	ServerIpv6                 *string // fd42:42:42:42::/112
	ForceGatewayIpv6           bool    // push "redirect-gateway ipv6"
	tunIpv6                    bool
	ecdhCurve                  string // prime256v1
	TlsCrypt                   string // tls-crypt.key
	CrlVerify                  string // crl.pem
	Auth                       string // SHA256
	Cipher                     string // AES-128-GCM
	dataCiphers                string // AES-128-GCM
	TlsServer                  bool
	TlsVersionMin              string  // 1.2
	TlsCipher                  string  // TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
	log                        string  // /var/log/openvpn.log
	Routes                     []Route // 10.42.44.0 255.255.255.0
	// 10.42.78.0 255.255.255.0
	// 10.8.0.0 255.255.255.0
	RoutesPush []Route // "route 10.42.44.0 255.255.255.0"
	Push       []Push  // "dhcp-option DNS 10.8.0.1"
	// "dhcp-option DNS fd42:42:42:42::1"
	// "redirect-gateway def1 bypass-dhcp"
	// "tun-ipv6"
	// "routes-ipv6 2000::/3"
	// "redirect-gateway ipv6"
}

var regIp = regexp.MustCompile("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")

func isIpv4(addr string) bool {
	return regIp.MatchString(addr)
}

func (config *OvpnConfig) GetCrlPath() string {
	return shell.AbsolutizePath(config.SourceFile, config.CrlVerify)
}

func (config *OvpnConfig) GetTlsCryptPath() string {
	return shell.AbsolutizePath(config.SourceFile, config.TlsCrypt)
}

func (config *OvpnConfig) GetCcdPath() string {
	return shell.AbsolutizePath(config.SourceFile, config.ClientConfigDir)
}

func ParseServerConf(file string) *OvpnConfig {
	if !shell.FileExist(file) {
		log.Printf("OpenVPN server not configured at '%s', starting with defaults", file)
		//setDefaults(config)
		return nil
	}

	log.Printf("Reading openvpn server config '%s'", file)
	config := new(OvpnConfig)
	config.SourceFile = file
	config.ServiceName = extractServiceName(file) // keep only the 'instance-name' from path like /etc/openvpn/[instance-name].conf
	config.TunMtu = -1
	config.Fragment = -1
	config.Mssfix = -1
	parseServerConfLines(config, strings.Split(shell.ReadFile(file), "\n"))

	log.Printf("  -> network: %s", config.Server)
	log.Printf("  -> management address: %s", config.Management)

	log.Printf("  -> ccd dir: '%s'", config.GetCcdPath())

	if len(config.ca) > 0 {
		cert := ReadIssuedCertificate(shell.AbsolutizePath(file, config.ca))
		if cert != nil {
			config.caCert = cert
		}
		log.Printf("  -> reading ca certificate: '%s'%s", config.ca, buildCertSimpleInfo(cert))
	}
	if len(config.Cert) > 0 {

		x509cert := ReadCertificate(shell.AbsolutizePath(file, config.Cert))
		if x509cert != nil {
			cert := mapX509ToCertificate(x509cert)
			if cert != nil {
				config.ServerCert = cert
				config.MasterCn = cert.CommonName
			}
			str := buildCertSimpleInfo(cert)
			if !isServerCert(x509cert) {
				str += ", invalid cert type for server"
			}
			log.Printf("  -> reading server certificate: '%s'%s", config.Cert, str)
		} else {
			log.Printf("  -> server certificate '%s' is missing !!!", config.Cert)
		}
	}
	if len(config.CrlVerify) > 0 {
		revList, _ := readCertificateRevocationList(config.GetCrlPath())
		if revList != nil {
			log.Printf("  -> CRL %s", buildDateExpire(revList.NextUpdate))
		} else {
			log.Printf("Cant read CRL !!!")
		}
	}

	return config
}

func buildCertSimpleInfo(cert *IssuedCertificate) string {
	str := ""
	if cert != nil {
		str += ", cn=" + cert.CommonName
		str += ", serial=" + bigIntToString(cert.SerialNumber)
		str += ", " + buildDateExpire(cert.ExpiresAt)
	} else {
		str = "missing"
	}
	return str
}

func buildDateExpire(t time.Time) string {
	if t.Before(time.Now()) {
		secondBehind := int64(time.Now().Sub(t).Seconds())
		return "expired since " + strconv.FormatInt(secondBehind, 10) + " seconds"
	} else {
		secondAbove := int64(t.Sub(time.Now()).Seconds())
		return "expires in " + strconv.FormatInt(secondAbove, 10) + " seconds"
	}
}

func parseServerConfLines(config *OvpnConfig, lines []string) {
	for _, line := range lines {
		line = strings.TrimLeft(line, " ")
		if len(line) == 0 {
			continue
		}
		commented := false
		if line[0:1] == "#" {
			line = strings.TrimLeft(line, "# ")
			commented = true
		}
		parseServerConfLine(config, line, commented)
	}
}

func extractServiceName(filename string) string {
	filename = path.Base(filename)
	extension := filepath.Ext(filename)
	return filename[0 : len(filename)-len(extension)]
}

func parseServerConfLine(config *OvpnConfig, line string, commented bool) {
	key, value := getKeyValue(line)

	switch {
	case key == "server":
		config.Server = getValueWithoutComment(line)
	case key == "port":
		if n, err := getIntValueWithoutComment(line); err == nil {
			config.Port = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "proto":
		config.proto = getValueWithoutComment(line)
	case key == "dev":
		config.dev = getValueWithoutComment(line)
	case key == "tun-mtu":
		if n, err := getIntValueWithoutComment(line); err == nil {
			config.EnableMtu = true
			config.TunMtu = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "fragment":
		if n, err := getIntValueWithoutComment(line); err == nil {
			config.Fragment = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "user":
		config.user = getValueWithoutComment(line)
	case key == "group":
		config.group = getValueWithoutComment(line)
	case key == "mssfix":
		if n, err := getIntValueWithoutComment(line); err == nil {
			config.Mssfix = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "management":
		config.Management = getValueWithoutComment(line)
	case key == "ca":
		config.ca = getValueWithoutComment(line)
	case key == "cert":
		config.Cert = getValueWithoutComment(line)
	case key == "key":
		config.Key = getValueWithoutComment(line)
	case key == "dh":
		config.dh = getValueWithoutComment(line)
	case key == "ifconfig-pool-persist":
		config.ifconfigPoolPersist = getValueWithoutComment(line)
	case key == "keepalive":
		config.keepalive = getValueWithoutComment(line)
	case key == "comp-lzo":
		config.CompLzo = true
	case key == "allow-compression":
		config.allowCompression = true
	case key == "persist-key":
		config.persistKey = true
	case key == "persist-tun":
		config.persistTun = true
	case key == "status":
		config.status = getValueWithoutComment(line)
	case key == "verb":
		if n, err := getIntValueWithoutComment(line); err == nil {
			config.verb = n
		} else {
			log.Printf("failed to parse int %s\n", line)
		}
	case key == "client-config-dir":
		config.ClientConfigDir = getValueWithoutComment(line)
	case key == "client-to-client":
		config.ClientToClient = true
	case key == "duplicate-cn":
		config.DuplicateCn = true
	case key == "topology":
		config.topology = getValueWithoutComment(line)
	case key == "server-ipv6":
		serverIpv6 := getValueWithoutComment(line)
		if serverIpv6 != "" {
			config.ServerIpv6 = &serverIpv6
		}
	case key == "tun-ipv6":
		config.tunIpv6 = true
	case key == "ecdh-curve":
		config.ecdhCurve = getValueWithoutComment(line)
	case key == "tls-crypt":
		config.TlsCrypt = getValueWithoutComment(line)
	case key == "crl-verify":
		config.CrlVerify = getValueWithoutComment(line)
	case key == "auth":
		config.Auth = getValueWithoutComment(line)
	case key == "cipher":
		config.Cipher = getValueWithoutComment(line)
	case key == "ncp-ciphers":
		config.dataCiphers = getValueWithoutComment(line)
	case key == "data-ciphers":
		config.dataCiphers = getValueWithoutComment(line)
	case key == "tls-server":
		config.TlsServer = true
	case key == "tls-version-min":
		config.TlsVersionMin = getValueWithoutComment(line)
	case key == "tls-cipher":
		config.TlsCipher = getValueWithoutComment(line)
	case key == "log":
		config.log = getValueWithoutComment(line)
	case key == "route":
		if route, err := getRouteValueWithComment(line); err == nil {
			config.Routes = append(config.Routes, route)
		} else {
			log.Printf("failed to line %v\n", err)
		}
	case key == "push":
		value, comment := getQuotedValueAndComment(value)
		//log.Printf("parsed push [%d] [%s] [%s]", commented, value, comment)
		//getQuotedValueWithoutComment(line)
		extractPushConfig(config, !commented, value, comment)

	default:
		log.Printf("skipped '%s'", line)
	}
}

func extractPushConfig(config *OvpnConfig, enabled bool, line string, comment string) {
	if !enabled {
		return
	}
	line = strings.TrimRight(line, " ")
	line = strings.TrimLeft(line, " ")
	parts := strings.Split(line, " ")

	if parts[0] == "redirect-gateway" {
		parts = parts[1:]
		for _, part := range parts {
			if part == "def1" {
				config.ForceGatewayIpv4 = true
			} else if part == "ipv6" {
				config.ForceGatewayIpv6 = true
			} else if part == "bypass-dhcp" {
				config.ForceGatewayIpv4ExceptDhcp = true
			} else if part == "bypass-dns" {
				config.ForceGatewayIpv4ExceptDns = true
			} else {
				log.Printf("Unrecognized redirect-gateway option '%s'", part)
			}
		}
	} else if parts[0] == "dhcp-option" && parts[1] == "DNS" {
		if isIpv4(parts[2]) {
			config.DnsIpv4 = &parts[2]
		} else {
			config.DnsIpv6 = &parts[2]
		}
	} else if parts[0] == "route" {
		if route, err := getRouteQuotedValue(parts[1:]); err == nil {
			route.Description = comment
			config.RoutesPush = append(config.RoutesPush, route)
		} else {
			log.Printf("failed to line %v\n", err)
		}
	} else {
		log.Printf("import push '%v'", parts)

		// TODO: extract:
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
		config.Push = append(config.Push, Push{Enabled: enabled, Name: parts[0], Value: line, Comment: comment})
	}
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
		line = line[p+1 : len(line)]
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
		line = line[p+1 : len(line)]
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

func getRouteQuotedValue(parts []string) (Route, error) {
	var route Route
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
		value = line[p+1 : len(line)]
	}
	if n, err := strconv.Atoi(value); err == nil {
		return n, nil
	} else {
		log.Printf("error: %s '%s' is not an integer", key, value)
		return -1, err
	}
}

func InitServerConf() *OvpnConfig {
	config := new(OvpnConfig)
	config.Port = 1194
	config.proto = "udp"
	config.dev = "tun"
	config.Management = "localhost 7505"
	config.ca = "easyrsa/pki/ca.crt"
	config.Cert = "easyrsa/pki/issued/server.crt"
	config.Key = "easyrsa/pki/private/server.key"
	config.ifconfigPoolPersist = "ipp.txt"
	config.keepalive = "10 120"
	config.persistKey = true
	config.persistTun = true
	config.status = "openvpn-status.log"
	config.verb = 1
	config.ClientConfigDir = "ccd"
	config.TlsVersionMin = "1.0"
	config.CrlVerify = "easyrsa/pki/crl.pem"
	config.Routes = make([]Route, 0)
	config.RoutesPush = make([]Route, 0)
	config.dh = "easyrsa/pki/dh.pem"
	//config.
	return config
}

func BuildConfig(config OvpnConfig) []byte {

	var lines = make([]string, 0)

	if len(config.Server) > 0 {
		lines = append(lines, fmt.Sprintf("server %s", config.Server))
	}
	if config.Port != 0 {
		lines = append(lines, fmt.Sprintf("port %d", config.Port))
	}
	if len(config.proto) > 0 {
		lines = append(lines, fmt.Sprintf("proto %s", config.proto))
	}
	if len(config.dev) > 0 {
		lines = append(lines, fmt.Sprintf("dev %s", config.dev))
	}
	if config.EnableMtu && config.TunMtu >= 0 {
		lines = append(lines, fmt.Sprintf("tun-mtu %d", config.TunMtu))
	}
	if config.Fragment > 0 {
		lines = append(lines, fmt.Sprintf("fragment %d", config.Fragment))
	}
	if len(config.user) > 0 {
		lines = append(lines, fmt.Sprintf("user %s", config.user))
	}
	if len(config.group) > 0 {
		lines = append(lines, fmt.Sprintf("group %s", config.group))
	}
	if config.Mssfix >= 0 {
		lines = append(lines, fmt.Sprintf("mssfix %d", config.Mssfix))
	}
	if len(config.Management) > 0 {
		lines = append(lines, fmt.Sprintf("management %s", config.Management))
	}
	if len(config.ca) > 0 {
		lines = append(lines, fmt.Sprintf("ca %s", config.ca))
	}
	if len(config.Cert) > 0 {
		lines = append(lines, fmt.Sprintf("cert %s", config.Cert))
	}
	if len(config.Key) > 0 {
		lines = append(lines, fmt.Sprintf("key %s", config.Key))
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
	if config.CompLzo {
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
	if len(config.ClientConfigDir) > 0 {
		lines = append(lines, fmt.Sprintf("client-config-dir %s", config.ClientConfigDir))
	}
	if config.ClientToClient {
		lines = append(lines, fmt.Sprintf("client-to-client"))
	}
	if config.DuplicateCn {
		lines = append(lines, fmt.Sprintf("duplicate-cn"))
	}
	if len(config.topology) > 0 {
		lines = append(lines, fmt.Sprintf("topology %s", config.topology))
	}
	if config.ServerIpv6 != nil && len(*config.ServerIpv6) > 0 {
		lines = append(lines, fmt.Sprintf("server-ipv6 %s", config.ServerIpv6))
		if config.tunIpv6 {
			// tun-ipv6 is for old clients
			lines = append(lines, fmt.Sprintf("tun-ipv6"))
		}
	}

	if len(config.ecdhCurve) > 0 {
		lines = append(lines, fmt.Sprintf("ecdh-curve %s", config.ecdhCurve))
	}
	if len(config.TlsCrypt) > 0 {
		lines = append(lines, fmt.Sprintf("tls-crypt %s", config.TlsCrypt))
	}
	if len(config.CrlVerify) > 0 {
		if _, err := os.Stat(config.CrlVerify); err == nil {
			lines = append(lines, fmt.Sprintf("crl-verify %s", config.CrlVerify))
		}
	}
	if len(config.Auth) > 0 {
		lines = append(lines, fmt.Sprintf("auth %s", config.Auth))
	}
	if len(config.Cipher) > 0 {
		lines = append(lines, fmt.Sprintf("cipher %s", config.Cipher))
	}
	if len(config.dataCiphers) > 0 {
		lines = append(lines, fmt.Sprintf("data-ciphers %s", config.dataCiphers))
	}
	if config.TlsServer {
		lines = append(lines, fmt.Sprintf("tls-server"))
	}
	if len(config.TlsVersionMin) > 0 {
		lines = append(lines, fmt.Sprintf("tls-version-min %s", config.TlsVersionMin))
	}
	if len(config.TlsCipher) > 0 {
		lines = append(lines, fmt.Sprintf("tls-cipher %s", config.TlsCipher))
	}
	if len(config.log) > 0 {
		lines = append(lines, fmt.Sprintf("log %s", config.log))
	}
	if len(config.Routes) > 0 {
		lines = append(lines, "")
		for _, route := range config.Routes {
			lines = append(lines, formatRoute(route))
		}
	}
	if len(config.RoutesPush) > 0 {
		lines = append(lines, "")
		for _, route := range config.RoutesPush {
			lines = append(lines, formatRoutePush(route))
		}
	}
	if config.ForceGatewayIpv4 {
		options := ""
		if config.ForceGatewayIpv4ExceptDhcp {
			options = options + " bypass-dhcp"
		}
		if config.ForceGatewayIpv4ExceptDns {
			options = options + " bypass-dns"
		}
		lines = append(lines, fmt.Sprintf("push \"redirect-gateway def1%s\"", options))
	}
	if config.ForceGatewayIpv6 {
		lines = append(lines, "push \"redirect-gateway ipv6\"")
	}
	if config.DnsIpv4 != nil && len(*config.DnsIpv4) > 0 {
		lines = append(lines, fmt.Sprintf("push \"dhcp-option DNS %s\"", *config.DnsIpv4))
	}
	if config.DnsIpv6 != nil && len(*config.DnsIpv6) > 0 {
		lines = append(lines, fmt.Sprintf("push \"dhcp-option DNS %s\"", *config.DnsIpv6))
	}
	if len(config.Push) > 0 {
		lines = append(lines, "")
		for _, s := range config.Push {
			lines = append(lines, formatPush(s))
		}
	}
	lines = append(lines, "")
	//log.Printf("config: %s", strings.Join(lines, "\n"))
	return []byte(strings.Join(lines, "\n"))
}

func formatPush(push Push) string {
	var line = ""
	if !push.Enabled {
		line += "# "
	}
	line += "push \"" + strings.Replace(push.Value, "\"", "\\\"", -1) + "\""
	if len(push.Comment) > 0 {
		line += " ## " + push.Comment
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

func formatRoutePush(route Route) string {
	var parts = make([]string, 0)
	parts = append(parts, "push \"route")
	parts = append(parts, route.Address)
	parts = append(parts, route.Netmask)
	parts = append(parts, "\"")
	if len(route.Description) > 0 {
		parts = append(parts, "#")
		parts = append(parts, route.Description)
	}
	return strings.Join(parts, " ")
}

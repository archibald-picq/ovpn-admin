package openvpn

import (
	"fmt"
	"os"
	"rpiadm/backend/shell"
	"strings"
)

func RenderClientConfig(
	servers []string,
	config *OvpnConfig,
	explicitExitNotify bool,
	authNocache bool,
	address string,
	VerifyX509Name bool,
	outboundIp string,
	masterCn string,
	easyrsaDirPath string,
	authByPassword bool,
	username string,
) []byte {
	var hosts []OpenvpnServer
	for _, server := range servers {
		if len(server) > 0 {
			parts := strings.SplitN(server, ":", 3)
			l := len(parts)
			if l > 2 {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1], Protocol: parts[2]})
			} else {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1]})
			}
		}
	}

	if len(hosts) == 0 {
		if len(address) > 0 {
			parts := strings.SplitN(address, ":", 2)
			if len(parts) == 1 {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: fmt.Sprintf("%d", config.Port)})
			} else {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1]})
			}
		} else {
			hosts = append(hosts, OpenvpnServer{Host: outboundIp, Port: fmt.Sprintf("%d", config.Port)})
		}
	}

	//log.Infof("hosts for %s\n %v", username, hosts)

	conf := OpenvpnClientConfig{}
	conf.Hosts = hosts
	conf.CA = shell.ReadFile(easyrsaDirPath + "/pki/ca.crt")
	if _, err := os.Stat(easyrsaDirPath + "/pki/ta.key"); err == nil {
		conf.TLS = shell.ReadFile(easyrsaDirPath + "/pki/ta.key")
	}
	if len(masterCn) > 0 && VerifyX509Name {
		conf.CertCommonName = masterCn
	}
	if config.CompLzo {
		conf.CompLzo = true
	}
	if len(config.TlsCrypt) > 0 {
		conf.TlsCrypt = stripDashComments(shell.ReadFile(config.GetTlsCryptPath()))
	}

	conf.Auth = config.Auth
	conf.ExplicitExitNotify = explicitExitNotify
	conf.AuthNocache = authNocache
	conf.Cipher = config.Cipher
	conf.TlsClient = config.TlsServer
	conf.TlsVersionMin = config.TlsVersionMin
	conf.TlsCipher = config.TlsCipher
	conf.Cert = removeCertificatText(shell.ReadFile(easyrsaDirPath + "/pki/issued/" + username + ".crt"))
	conf.Key = shell.ReadFile(easyrsaDirPath + "/pki/private/" + username + ".key")

	conf.PasswdAuth = authByPassword

	return buildOvpnClientConfigFile(conf)
}

func buildOvpnClientConfigFile(conf OpenvpnClientConfig) []byte {
	var lines = make([]string, 0)

	lines = append(lines, "client")
	if conf.ExplicitExitNotify {
		lines = append(lines, "explicit-exit-notify")
	}
	lines = append(lines, "dev tun")
	lines = append(lines, "proto udp")

	for _, server := range conf.Hosts {
		proto := ""
		if len(server.Protocol) > 0 {
			proto = " " + server.Protocol
		}
		lines = append(lines, "remote "+server.Host+" "+server.Port+proto)
	}

	lines = append(lines, "resolv-retry infinite")
	lines = append(lines, "nobind")
	lines = append(lines, "persist-key")
	lines = append(lines, "persist-tun")

	lines = append(lines, "remote-cert-tls server")

	if conf.CompLzo {
		lines = append(lines, "comp-lzo")
	}
	lines = append(lines, "verb 3")

	if len(conf.CertCommonName) > 0 {
		lines = append(lines, "verify-x509-name "+conf.CertCommonName+" name")
	}

	if len(conf.Auth) > 0 {
		lines = append(lines, "auth "+conf.Auth)
	}

	if conf.AuthNocache {
		lines = append(lines, "auth-nocache")
	}

	if len(conf.Cipher) > 0 {
		lines = append(lines, "cipher "+conf.Cipher)
	}

	if conf.TlsClient {
		lines = append(lines, "tls-client")
	}

	if len(conf.TlsVersionMin) > 0 {
		lines = append(lines, "tls-version-min "+conf.TlsVersionMin)
	}

	if len(conf.TlsCipher) > 0 {
		lines = append(lines, "tls-cipher "+conf.TlsCipher)
	}

	lines = append(lines, "ignore-unknown-option block-outside-dns")
	lines = append(lines, "setenv opt block-outside-dns # Prevent Windows 10 DNS leak")

	if conf.PasswdAuth {
		lines = append(lines, "auth-user-pass")
	}

	lines = append(lines, "<cert>")
	lines = append(lines, conf.Cert)
	lines = append(lines, "</cert>")

	lines = append(lines, "<key>")
	lines = append(lines, conf.Key)
	lines = append(lines, "</key>")

	lines = append(lines, "<ca>")
	lines = append(lines, conf.CA)
	lines = append(lines, "</ca>")

	if len(conf.TLS) > 0 {
		lines = append(lines, "<tls-auth>")
		lines = append(lines, conf.TLS)
		lines = append(lines, "</tls-auth>")
	}
	if len(conf.TlsCrypt) > 0 {
		lines = append(lines, "<tls-crypt>")
		lines = append(lines, conf.TlsCrypt)
		lines = append(lines, "</tls-crypt>")
	}

	return []byte(strings.Join(lines, "\n"))
}

func stripDashComments(content string) string {
	lines := strings.Split(content, "\n")
	output := make([]string, 0)
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			output = append(output, line)
		}
	}
	//output = append(output, "")
	return strings.Join(output, "\n")
}

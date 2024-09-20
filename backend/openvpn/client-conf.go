package openvpn

import (
	"bytes"
	"fmt"
	"os"
	"rpiadm/backend/shell"
	"strings"
	"text/template"
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
	serverConfFile string,
	easyrsaDirPath string,
	t *template.Template,
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
		conf.TlsCrypt = stripDashComments(shell.ReadFile(shell.AbsolutizePath(serverConfFile, config.TlsCrypt)))
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

	var tmp bytes.Buffer
	err := t.Execute(&tmp, conf)
	if err != nil {
		//log.Errorf("something goes wrong during rendering config for %s", username)
		//log.Debugf("rendering config for %s failed with error %v", username, err)
	}

	hosts = nil

	//log.Printf("Rendered config for user %s: %+v", username, tmp.String())

	return tmp.Bytes()
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

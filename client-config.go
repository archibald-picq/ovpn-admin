package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	log "github.com/sirupsen/logrus"
)

type OpenvpnClientConfig struct {
	Hosts              []OpenvpnServer
	CA                 string
	Cert               string
	Key                string
	TLS                string
	PasswdAuth         bool
	TlsCrypt           string
	CompLzo            bool
	CertCommonName     string
	ExplicitExitNotify bool
	Auth               string
	AuthNocache        bool
	Cipher             string
	TlsClient          bool
	TlsVersionMin      string
	TlsCipher          string
}
func (app *OvpnAdmin) renderClientConfig(username string) string {
	_, _, err := checkUserExist(username)
	if err != nil {
		log.Warnf("user \"%s\" not found", username)
		return fmt.Sprintf("user \"%s\" not found", username)
	}
	var hosts []OpenvpnServer

	for _, server := range *openvpnServer {
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
		if len(app.applicationPreferences.Preferences.Address) > 0 {
			parts := strings.SplitN(app.applicationPreferences.Preferences.Address, ":", 2)
			if len(parts) == 1 {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: fmt.Sprintf("%d", app.serverConf.port)})
			} else {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1]})
			}
		} else {
			hosts = append(hosts, OpenvpnServer{Host: app.outboundIp.String(), Port: fmt.Sprintf("%d", app.serverConf.port)})
		}
	}

	log.Infof("hosts for %s\n %v", username, hosts)

	conf := OpenvpnClientConfig{}
	conf.Hosts = hosts
	conf.CA = fRead(*easyrsaDirPath + "pki/ca.crt")
	if _, err := os.Stat(*easyrsaDirPath + "pki/ta.key"); err == nil {
		conf.TLS = fRead(*easyrsaDirPath + "pki/ta.key")
	}
	if len(app.masterCn) > 0 && app.applicationPreferences.Preferences.VerifyX509Name {
		conf.CertCommonName = app.masterCn
	}
	if app.serverConf.compLzo {
		conf.CompLzo = true
	}
	if len(app.serverConf.tlsCrypt) > 0 {
		conf.TlsCrypt = fRead(absolutizePath(*serverConfFile, app.serverConf.tlsCrypt))
	}

	conf.Auth = app.serverConf.auth
	conf.ExplicitExitNotify = app.applicationPreferences.Preferences.ExplicitExitNotify
	conf.AuthNocache = app.applicationPreferences.Preferences.AuthNocache
	conf.Cipher = app.serverConf.cipher
	conf.TlsClient = app.serverConf.tlsServer
	conf.TlsVersionMin = app.serverConf.tlsVersionMin
	conf.TlsCipher = app.serverConf.tlsCipher

	conf.Cert = removeCertificatText(fRead(*easyrsaDirPath + "/pki/issued/" + username + ".crt"))
	conf.Key = fRead(*easyrsaDirPath + "/pki/private/" + username + ".key")

	conf.PasswdAuth = *authByPassword

	t := app.getClientConfigTemplate()

	var tmp bytes.Buffer
	err = t.Execute(&tmp, conf)
	if err != nil {
		log.Errorf("something goes wrong during rendering config for %s", username)
		log.Debugf("rendering config for %s failed with error %v", username, err)
	}

	hosts = nil

	log.Tracef("Rendered config for user %s: %+v", username, tmp.String())

	return fmt.Sprintf("%+v", tmp.String())
}

func (app *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		err := fDelete(ccdArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(ccdArchivePath, *masterHost+downloadCcdApiUrl+"?token="+app.masterSyncToken, app.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"time"

	log "github.com/sirupsen/logrus"
)

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *easyrsaDirPath + "/pki/ca.crt"
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("error read file %s: %s", caCertPath, err.Error())
	}

	certPem, _ := pem.Decode(caCert)
	certPemBytes := certPem.Bytes

	cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Errorf("error parse certificate ca.crt: %s", err.Error())
		return time.Now()
	}

	return cert.NotAfter
}

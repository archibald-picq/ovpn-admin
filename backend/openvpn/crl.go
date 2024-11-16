package openvpn

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"rpiadm/backend/shell"
	"strings"
	"time"
)

func readCertificateRevocationList(path string) (*x509.RevocationList, error) {
	caCert, err := os.ReadFile(path)
	if err != nil {
		log.Printf("error read file %s: %s", path, err.Error())
		return nil, err
	}

	certPem, _ := pem.Decode(caCert)

	revList, err := x509.ParseRevocationList(certPem.Bytes)
	if err != nil {
		log.Printf("error reading certificate '%s': %s", path, err.Error())
		return nil, err
	}
	return revList, nil
}

func (easyrsa Easyrsa) UpdateCertificateRevocationList(path string) (*string, error) {
	revList, err := readCertificateRevocationList(path)
	if err != nil {
		return nil, err
	}
	//log.Printf("CRL expires at %s, NOW is %s", revList.NextUpdate.Format(time.RFC3339), time.Now().Format(time.RFC3339))
	if revList.NextUpdate.Before(time.Now()) {
		log.Printf("  -> CRL expired since %d seconds", int64(time.Now().Sub(revList.NextUpdate).Seconds()))
		easyrsa.RebuildClientRevocationList()
	} else if int64(revList.NextUpdate.Sub(time.Now()).Hours()) > 72 {
		log.Printf("  -> CRL expires in %d seconds", int64(revList.NextUpdate.Sub(time.Now()).Seconds()))
		easyrsa.RebuildClientRevocationList()
	} else {
		log.Printf("  -> CRL: %d certificates revoked", len(revList.RevokedCertificateEntries))
	}
	//return mapX509ToCertificate(x509cert)
	return nil, nil
}

func GetCrlList(crlFile string, certs []*Certificate) ([]*RevokedCert, error) {
	out, err := shell.RunBash(fmt.Sprintf("openssl crl -text -noout -in %s", crlFile))
	crls := make([]*RevokedCert, 0)
	if err != nil {
		return crls, err
	}
	//log.Printf("stdout: %s", out)
	//log.Printf("stderr: %s", err)

	lines := strings.Split(out, "\n")
	var currentEntry *RevokedCert

	for _, line := range lines {
		line = strings.Trim(line, " ")
		log.Printf("parse '%s'", line)
		if matches := regSerialNumber.FindStringSubmatch(line); len(matches) > 0 {
			if currentEntry != nil {
				crls = append(crls, currentEntry)
				currentEntry = nil
			}
			currentEntry = new(RevokedCert)
			currentEntry.SerialNumber = matches[1]
			log.Printf(" - new entry %s", currentEntry.SerialNumber)
		} else if matches := regRevocationDate.FindStringSubmatch(line); len(matches) > 0 {
			currentEntry.RevokedTime = parseDate(crlDateFormat, matches[1])
			log.Printf("   - new date %v", currentEntry.RevokedTime)
		}
	}

	if currentEntry != nil {
		crls = append(crls, currentEntry)
		currentEntry = nil
	}

	log.Printf("revoked entries: %d", len(crls))

	for _, crl := range crls {
		log.Printf("find cert for serial: %s", crl.SerialNumber)
		for _, cert := range certs {
			if cert.SerialNumber == crl.SerialNumber {
				crl.CommonName = &cert.Username
				crl.Cert = cert
			}
		}
	}

	return crls, nil
}

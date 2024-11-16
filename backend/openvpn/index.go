package openvpn

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/alessio/shellescape"
	"log"
	"rpiadm/backend/shell"
	"strings"
)

func (easyrsa Easyrsa) IndexTxtParserCertificate() []*Certificate {
	txt := shell.ReadFile(easyrsa.EasyrsaDirPath + "/pki/index.txt")
	var indexTxt = make([]*Certificate, 0)

	txtLinesArray := strings.Split(txt, "\n")
	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) <= 0 {
			continue
		}
		switch {
		case strings.HasPrefix(str[0], "V"):
			identity := strings.Join(str[4:], " ")
			indexTxt = append(indexTxt, BuildClientCertificate(identity, "V", str[1], nil, str[2], str[3]))
		case strings.HasPrefix(str[0], "R"):
			identity := strings.Join(str[5:], " ")
			indexTxt = append(indexTxt, BuildClientCertificate(identity, "R", str[1], &str[2], str[3], str[4]))
		}
	}
	return indexTxt
}

func (easyrsa Easyrsa) FindUnrevokedCertificate(username string) (*Certificate, []*Certificate) {
	all := easyrsa.IndexTxtParserCertificate()
	for _, cert := range all {
		//log.Printf("-> find %v = %v, %v = %v", cert.Username, username, cert.Flag, "V")
		if cert.Username == username && cert.Flag == "V" {
			return cert, all
		}
	}
	return nil, all
}

func (easyrsa Easyrsa) FindRevokedCertificate(commonName string, serialNumber string) (*Certificate, []*Certificate) {
	all := easyrsa.IndexTxtParserCertificate()
	for _, cert := range all {
		//log.Printf("-> find %v = %v, %v = %v", cert.Username, commonName, cert.Flag, "V")
		if cert.Username == commonName && cert.Flag == "R" && cert.SerialNumber == serialNumber {
			return cert, all
		}
	}
	return nil, all
}

func (easyrsa Easyrsa) FindCertificateBySerial(commonName string, serial string) (*Certificate, []*Certificate) {
	all := easyrsa.IndexTxtParserCertificate()
	for _, cert := range all {
		log.Printf("-> find %v = %v, %v = %v", cert.Username, commonName, cert.SerialNumber, serial)
		if cert.Username == commonName && cert.SerialNumber == serial {
			return cert, all
		}
	}
	return nil, all
}
func (easyrsa Easyrsa) IsPkiInited() bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/vars") && shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/private")
}

func CaCertExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/ca.crt")
}

func (easyrsa Easyrsa) IndexTxtExists() bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/index.txt")
}

func FindFirstServerCertIfExists(easyrsa Easyrsa, certicates []*Certificate) *IssuedCertificate {
	for _, cert := range certicates {
		x509cert, err := ReadCertificateX509(easyrsa.EasyrsaDirPath + "/pki/issued/" + cert.Username + ".crt")
		if err != nil {
			log.Printf("can't read '%s' certificate", cert.Username)
			continue
		}
		log.Printf("Cert '%s':", cert.Username)
		log.Printf(" - Validity: '%v'", x509cert.BasicConstraintsValid)
		log.Printf(" - ExtKeyUsage: '%v'", x509cert.ExtKeyUsage)
		if isServerCert(x509cert) {
			return mapX509ToCertificate(x509cert)
		}
	}
	return nil
}

func isServerCert(x509cert *x509.Certificate) bool {
	for _, usage := range x509cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func ReadCaCertIfExists(easyrsa Easyrsa) *IssuedCertificate {
	if shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/ca.crt") {
		x509cert := ReadCertificate(easyrsa.EasyrsaDirPath + "/pki/ca.crt")
		return mapX509ToCertificate(x509cert)

	}
	return nil
}

func InitPki(easyrsa Easyrsa) error {
	//if IndexTxtExists(easyrsa) {
	//	return nil
	//}
	err := shell.CreateDir(easyrsa.EasyrsaDirPath + "/pki")
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf(
		"cd %s && (echo yes | %s init-pki)",
		shellescape.Quote(easyrsa.EasyrsaDirPath),
		shellescape.Quote(easyrsa.EasyrsaBinPath),
	)

	o, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("Error init pki \"%s\", using \"cmd\" %s", err, cmd)
		return errors.New(fmt.Sprintf("Error init pki \"%s\"", err))
	}
	log.Printf("error %s", o)
	return nil
}

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

func IndexTxtParserCertificate(easyrsa Easyrsa) []*Certificate {
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

func IsPkiInited(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/vars") && shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/private")
}

func CaCertExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/ca.crt")
}

func IndexTxtExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/index.txt")
}

func FindFirstServerCertIfExists(easyrsa Easyrsa, certicates []*Certificate) *BaseCertificate {
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
			return MapX509ToCertificate(x509cert)
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

func ReadCaCertIfExists(easyrsa Easyrsa) *BaseCertificate {
	if shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/ca.crt") {
		return ReadCertificate(easyrsa.EasyrsaDirPath + "/pki/ca.crt")
	}
	return nil
}

func CertExists(easyrsa Easyrsa, commonName string) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/issued/" + commonName + ".crt")
}

//func IndexTxtExists(easyrsa Easyrsa) bool {
//	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/index.txt")
//}

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

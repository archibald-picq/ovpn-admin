package openvpn

import (
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

func PkiExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki")
}

func CaExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/private/ca.key")
}

func CaCertExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/ca.crt")
}

func ReadPkiCertIfExists(easyrsa Easyrsa, commonName string) *BaseCertificate {
	if CertExists(easyrsa, commonName) {
		return ReadCertificate(easyrsa.EasyrsaDirPath + "/pki/issued/" + commonName + ".crt")
	}
	return nil
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

func IndexTxtExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/index.txt")
}

func InitPki(easyrsa Easyrsa) error {
	if IndexTxtExists(easyrsa) {
		return nil
	}
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

func BuildCa(easyrsa Easyrsa) error {
	cmd := fmt.Sprintf(
		"cd %s && %s build-ca",
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

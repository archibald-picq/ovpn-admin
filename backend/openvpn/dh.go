package openvpn

import (
	"errors"
	"fmt"
	"gopkg.in/alessio/shellescape.v1"
	"log"
	"rpiadm/backend/shell"
)

func DhPemExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/dh.pem")
}

func CreateDhFile(easyrsa Easyrsa) error {
	if shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/dh.pem") {
		return nil
	}
	cmd := fmt.Sprintf(
		"cd %s && %s gen-dh 1>/dev/null",
		shellescape.Quote(easyrsa.EasyrsaDirPath),
		shellescape.Quote(easyrsa.EasyrsaBinPath),
	)

	log.Printf("cmd %s", cmd)
	o, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("Error generating DH file \"%s\", using \"cmd\" %s", err, cmd)
		return errors.New(fmt.Sprintf("Error generating DH file \"%s\"", err))
	}

	log.Printf("cert generated %s", o)
	return nil
}

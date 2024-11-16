package openvpn

import (
	"errors"
	"fmt"
	"gopkg.in/alessio/shellescape.v1"
	"log"
	"rpiadm/backend/shell"
	"time"
)

func (easyrsa Easyrsa) CreateServerCertificate(definition UserDefinition) (*Certificate, error) {
	log.Printf("CreateServerCertificate(%s)", definition.CommonName)

	if !validateUsername(definition.CommonName) {
		return nil, errors.New(fmt.Sprintf("Certificate commonName \"%s\" incorrect, you can use only %s\n", definition.CommonName, usernameRegexp))
	}

	if easyrsa.checkUserActiveExist(definition.CommonName) {
		return nil, errors.New(fmt.Sprintf("Certificate \"%s\" already exists", definition.CommonName))
	}

	cmdOptions := ""
	if definition.ExpiresAt != nil {
		log.Printf("specify start/end dates '%v'", definition.ExpiresAt)
		days := definition.ExpiresAt.Sub(time.Now()).Hours() / 24
		log.Printf("expires in %d days", days)

		cmdOptions = fmt.Sprintf("--days=%.0f", days)
	}

	cmd := fmt.Sprintf(
		"cd %s && "+
			"EASYRSA_REQ_COUNTRY=%s "+
			"EASYRSA_REQ_PROVINCE=%s "+
			"EASYRSA_REQ_CITY=%s "+
			"EASYRSA_REQ_ORG=%s "+
			"EASYRSA_REQ_OU=%s "+
			"EASYRSA_REQ_EMAIL=%s "+
			"%s --dn-mode=org --batch %s build-server-full %s nopass 1>/dev/null",
		shellescape.Quote(easyrsa.EasyrsaDirPath),
		shellescape.Quote(definition.Country),
		shellescape.Quote(definition.Province),
		shellescape.Quote(definition.City),
		shellescape.Quote(definition.Organisation),
		shellescape.Quote(definition.OrganisationUnit),
		shellescape.Quote(definition.Email),
		shellescape.Quote(easyrsa.EasyrsaBinPath),
		cmdOptions,
		shellescape.Quote(definition.CommonName),
	)

	log.Printf("cmd %s", cmd)
	output, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("Error creating server certificate \"%s\", using \"cmd\" %s", err, cmd)
		return nil, errors.New(fmt.Sprintf("Error creating server certificate \"%s\"", err))
	}

	log.Printf("cert generated %s", output)

	//if authByPassword {
	//	output, err := shell.RunBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", authDatabase, definition.CommonName, definition.Password))
	//	if err != nil {
	//		return nil, errors.New(fmt.Sprintf("Error creating user in DB \"%s\"", err))
	//	}
	//	log.Printf("create password for %s: %s", definition.CommonName, output)
	//}

	log.Printf("Certificate for user %s issued", definition.CommonName)

	cert, _ := easyrsa.FindUnrevokedCertificate(definition.CommonName)

	if cert != nil {
		return cert, nil
	}
	return nil, errors.New("cant find just created certificate")
}

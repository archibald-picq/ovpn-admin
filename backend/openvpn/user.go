package openvpn

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"os"
	"rpiadm/backend/shell"
	"strings"
)

func UserChangePassword(authDatabase, username, password string) error {
	o, _ := shell.RunBash(fmt.Sprintf("openvpn-user check --db.path %s --user %s | grep %s | wc -l", authDatabase, username, username))
	log.Printf(o)

	if err := ValidatePassword(password); err != nil {
		return err
	}

	if strings.TrimSpace(o) == "0" {
		log.Printf("Creating user in users.db")
		o, err := shell.RunBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", authDatabase, username, password))
		log.Printf(o)
		if err != nil {
			return err
		}
	}

	o, err := shell.RunBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", authDatabase, username, password))
	if err != nil {
		return err
	}
	log.Printf(o)
	//log.Printf("Password for user %s was changed", username)

	return nil
}

func RevokeCertificate(
	easyrsa Easyrsa,
	authByPassword bool,
	authDatabase string,
	client *Certificate,
) error {
	var shellOut string

	if (*client).Flag != "V" {
		return errors.New(fmt.Sprintf("Certificate %s is not valid state (is %s)", client.Username, client.Flag))
	}

	// patch file in case of filesystem error
	RestoreCertBySerial(easyrsa, client.SerialNumber, client.Username)

	cmd := fmt.Sprintf("cd %s && echo yes | %s revoke %s", easyrsa.EasyrsaDirPath, easyrsa.EasyrsaBinPath, client.Username)
	log.Printf("running %s", cmd)
	shellOut, err := shell.RunBash(cmd)
	if err != nil {
		log.Print(err)
		return errors.New(fmt.Sprintf("Error revoking certificate \"%s\"", err))
	}
	log.Printf(shellOut)

	if authByPassword {
		shellOut, err := shell.RunBash(fmt.Sprintf("openvpn-user revoke --db-path %s --user %s", authDatabase, client.Username))
		if err != nil {
			return errors.New(fmt.Sprintf("Error updateing DB \"%s\"", err))
		}
		log.Printf(shellOut)
	}

	(*client).Flag = "R"
	RebuildClientRevocationList(easyrsa)
	return nil
}

func UserDelete(easyrsa Easyrsa, certificate *Certificate) error {
	all := IndexTxtParserCertificate(easyrsa)
	for _, u := range all {
		if u.Username == certificate.Username {
			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
			(*u).Username = "DELETED-" + certificate.Username + "-" + uniqHash
			shell.WriteFile(easyrsa.EasyrsaDirPath+"/pki/index.txt", RenderIndexTxt(all))
			RebuildClientRevocationList(easyrsa)
			chmodFix(easyrsa.EasyrsaDirPath)
			(*certificate).Flag = "D"
			return nil
		}
	}
	return errors.New("certificate not found")
}

// https://community.openvpn.net/openvpn/ticket/623
func chmodFix(easyrsaDirPath string) {
	err := os.Chmod(easyrsaDirPath+"/pki", 0755)
	if err != nil {
		log.Printf(err.Error())
		return
	}
	err = os.Chmod(easyrsaDirPath+"/pki/crl.pem", 0644)
	if err != nil {
		log.Printf(err.Error())
		return
	}
}

func UserUnrevoke(easyrsa Easyrsa, authByPassword bool, authDatabase string, client *Certificate) error {
	all := IndexTxtParserCertificate(easyrsa)
	for idx, cert := range all {
		if cert.Username == client.Username {
			log.Printf("unrevoke %v", *client)

			if (*client).Flag != "R" {
				return errors.New(fmt.Sprintf("Certificate %s is not in revocated state (is %s)", client.Username, client.Flag))
			}

			RestoreCertBySerial(easyrsa, client.SerialNumber, client.Username)
			if authByPassword {
				_, _ = shell.RunBash(fmt.Sprintf("openvpn-user restore --db-path %s --user %s", authDatabase, client.Username))
			}

			all[idx].Flag = "V"

			rendered := RenderIndexTxt(all)
			//log.Printf(string(rendered))
			err := shell.WriteFile(easyrsa.EasyrsaDirPath+"/pki/index.txt", rendered)
			chmodFix(easyrsa.EasyrsaDirPath)
			if err != nil {
				log.Printf(err.Error())
				return err
			}
			RebuildClientRevocationList(easyrsa)
			return nil
		}
	}
	return errors.New("certificate not found")
}

func UserRotate(easyrsa Easyrsa, authByPassword bool, authDatabase string, username string, newDefinition *UserDefinition) error {
	all := IndexTxtParserCertificate(easyrsa)
	for _, cert := range all {
		if cert.Username == username {

			if cert.Flag != "V" {
				return errors.New(fmt.Sprintf("Certificate \"%s\" is already revoked", cert.Username))
			}
			_, err := shell.RunBash(fmt.Sprintf("cd %s && echo yes | %s revoke %s", easyrsa.EasyrsaDirPath, easyrsa.EasyrsaBinPath, cert.Username))
			if err != nil {
				return errors.New(fmt.Sprintf("Error revoking certificate \"%s\"", err))
			}

			if newDefinition == nil {
				newDefinition = new(UserDefinition)
				newDefinition.City = cert.City
				newDefinition.Province = cert.Province
				newDefinition.Country = cert.Country
				newDefinition.Organisation = cert.Organisation
				newDefinition.OrganisationUnit = cert.OrganisationUnit
				newDefinition.Email = cert.Email
			}
			newDefinition.CommonName = username
			newDefinition.Password = ""

			newCert, err := CreateClientCertificate(easyrsa, authByPassword, authDatabase, *newDefinition)
			if err != nil {
				return errors.New(fmt.Sprintf("Fail to create certificate for \"%s\": %s", cert.Username, err))
			}

			if authByPassword {
				shell.RunBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", authDatabase, username, newDefinition.Password))
			}
			cert.City = newCert.City
			cert.Province = newCert.Province
			cert.Country = newCert.Country
			cert.Organisation = newCert.Organisation
			cert.OrganisationUnit = newCert.OrganisationUnit
			cert.Email = newCert.Email
			cert.ExpirationDate = newCert.ExpirationDate
			cert.SerialNumber = newCert.SerialNumber
			cert.Flag = newCert.Flag
			cert.Filename = newCert.Filename

			writeIndex(easyrsa, all)
			RebuildClientRevocationList(easyrsa)
			chmodFix(easyrsa.EasyrsaDirPath)
			return nil
		}
	}
	return errors.New("certificate not found")
}

func writeIndex(easyrsa Easyrsa, data []*Certificate) {
	err := shell.WriteFile(easyrsa.EasyrsaDirPath+"/pki/index.txt", RenderIndexTxt(data))
	if err != nil {
		log.Printf("fail to write index.txt %s", err)
	}
}

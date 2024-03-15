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
	easyrsaBinPath string,
	easyrsaDirPath string,
	authByPassword bool,
	authDatabase string,
	client *Certificate,
) error {
	var shellOut string

	if (*client).Flag != "V" {
		return errors.New(fmt.Sprintf("Certificate %s is not valid state (is %s)", client.Username, client.Flag))
	}

	// patch file in case of filesystem error
	RestoreCertBySerial(easyrsaDirPath, client.SerialNumber, client.Username)

	cmd := fmt.Sprintf("cd %s && echo yes | %s revoke %s", easyrsaDirPath, easyrsaBinPath, client.Username)
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
	RebuildClientRevocationList(easyrsaBinPath, easyrsaDirPath)
	return nil
}

func UserDelete(easyrsaBinPath string, easyrsaDirPath string, certificate *Certificate) error {
	all := IndexTxtParserCertificate(easyrsaDirPath + "/pki")
	for _, u := range all {
		if u.Username == certificate.Username {
			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
			(*u).Username = "DELETED-" + certificate.Username + "-" + uniqHash
			shell.WriteFile(easyrsaDirPath+"/pki/index.txt", RenderIndexTxt(all))
			RebuildClientRevocationList(easyrsaBinPath, easyrsaDirPath)
			chmodFix(easyrsaDirPath)
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

func UserUnrevoke(easyrsaBinPath, pkiPath string, easyrsaDirPath string, authByPassword bool, authDatabase string, client *Certificate) error {
	all := IndexTxtParserCertificate(pkiPath)
	for idx, cert := range all {
		if cert.Username == client.Username {
			log.Printf("unrevoke %v", *client)

			if (*client).Flag != "R" {
				return errors.New(fmt.Sprintf("Certificate %s is not in revocated state (is %s)", client.Username, client.Flag))
			}

			RestoreCertBySerial(easyrsaDirPath, client.SerialNumber, client.Username)
			if authByPassword {
				_, _ = shell.RunBash(fmt.Sprintf("openvpn-user restore --db-path %s --user %s", authDatabase, client.Username))
			}

			all[idx].Flag = "V"

			rendered := RenderIndexTxt(all)
			//log.Printf(string(rendered))
			err := shell.WriteFile(easyrsaDirPath+"/pki/index.txt", rendered)
			chmodFix(easyrsaDirPath)
			if err != nil {
				log.Printf(err.Error())
				return err
			}
			RebuildClientRevocationList(easyrsaBinPath, easyrsaDirPath)
			return nil
		}
	}
	return errors.New("certificate not found")
}

func UserRotate(easyrsaBinPath string, pkiPath string, easyrsaDirPath string, authByPassword bool, authDatabase string, username string, newPassword string, certificate *Certificate) error {
	all := IndexTxtParserCertificate(pkiPath)
	for _, cert := range all {
		if cert.Username == certificate.Username {

			if cert.Flag != "V" {
				return errors.New(fmt.Sprintf("Certificate \"%s\" is already revoked", cert.Username))
			}
			_, err := shell.RunBash(fmt.Sprintf("cd %s && echo yes | %s revoke %s", easyrsaDirPath, easyrsaBinPath, cert.Username))
			if err != nil {
				return errors.New(fmt.Sprintf("Error revoking certificate \"%s\"", err))
			}

			_, err = UserCreateCertificate(easyrsaDirPath, easyrsaBinPath, authByPassword, authDatabase, UserDefinition{
				Username:         cert.Username,
				Password:         newPassword,
				City:             cert.City,
				Province:         cert.Province,
				Country:          cert.Country,
				Organisation:     cert.Organisation,
				OrganisationUnit: cert.OrganisationUnit,
				Email:            cert.Email,
			})
			if err != nil {
				return errors.New(fmt.Sprintf("Fail to create certificate for \"%s\": %s", cert.Username, err))
			}

			if authByPassword {
				shell.RunBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", authDatabase, username, newPassword))
			}

			shell.WriteFile(easyrsaDirPath+"/pki/index.txt", RenderIndexTxt(all))
			RebuildClientRevocationList(easyrsaBinPath, easyrsaDirPath)
			chmodFix(easyrsaDirPath)
			return nil
		}
	}
	return errors.New("certificate not found")
}

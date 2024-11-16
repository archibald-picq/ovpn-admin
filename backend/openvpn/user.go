package openvpn

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"math/big"
	"os"
	"rpiadm/backend/shell"
	"strings"
	"time"
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

func (easyrsa Easyrsa) RevokeCertificate(commonName string, serialNumber *big.Int) error {
	serialStr := bigIntToString(serialNumber)

	if !shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/issued/"+commonName+".crt") &&
		shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/revoked/certs_by_serial/"+serialStr+".crt") &&
		!shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/private/"+commonName+".key") &&
		shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/revoked/private_by_serial/"+serialStr+".key") &&
		!shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/reqs/"+commonName+".req") &&
		shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/revoked/reqs_by_serial/"+serialStr+".req") {

		cert, all := easyrsa.FindCertificateBySerial(commonName, serialStr)
		if cert.Flag == "V" {
			(*cert).Flag = "R"
			(*cert).RevocationDate = time.Now().Format(time.RFC3339)

			easyrsa.WriteIndexTxt(all)
		}

		return nil
	}

	expiredPath := easyrsa.EasyrsaDirPath + "/pki/revoked/certs_by_serial/" + serialStr + ".crt"
	log.Printf("check %s", expiredPath)
	if shell.DeleteFileIfExists(expiredPath) != nil {
		log.Printf("Can't delete file %s", expiredPath)
	}

	expiredPath = easyrsa.EasyrsaDirPath + "/pki/revoked/private_by_serial/" + serialStr + ".key"
	log.Printf("check %s", expiredPath)
	if shell.DeleteFileIfExists(expiredPath) != nil {
		log.Printf("Can't delete file %s", expiredPath)
	}

	expiredPath = easyrsa.EasyrsaDirPath + "/pki/revoked/reqs_by_serial/" + serialStr + ".req"
	log.Printf("check %s", expiredPath)
	if shell.DeleteFileIfExists(expiredPath) != nil {
		log.Printf("Can't delete file %s", expiredPath)
	}

	cmd := fmt.Sprintf("cd %s && echo yes | %s revoke %s", easyrsa.EasyrsaDirPath, easyrsa.EasyrsaBinPath, commonName)
	log.Printf("running %s", cmd)
	shellOut, err := shell.RunBash(cmd)
	if err != nil {
		log.Print(err)
		return errors.New(fmt.Sprintf("Error revoking certificate \"%s\"", err))
	}
	log.Printf(shellOut)

	easyrsa.RebuildClientRevocationList()
	return nil
}

func UserDelete(easyrsa Easyrsa, certificate *Certificate) error {
	all := easyrsa.IndexTxtParserCertificate()
	for _, u := range all {
		if u.Username == certificate.Username {
			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
			(*u).Username = "DELETED-" + certificate.Username + "-" + uniqHash
			easyrsa.WriteIndexTxt(all)
			easyrsa.RebuildClientRevocationList()
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

func bigIntToString(str *big.Int) string {
	return strings.ToUpper(hex.EncodeToString(str.Bytes()))
}

func HexToBigInt(str string) *big.Int {
	i := new(big.Int)
	i.SetString(str, 16)
	return i
}

func (easyrsa Easyrsa) UnrevokeCertificate(authByPassword bool, authDatabase string, commonName string, serialNumber string) (*Certificate, error) {
	cert, all := easyrsa.FindRevokedCertificate(commonName, serialNumber)

	if cert == nil {
		return nil, errors.New(fmt.Sprintf("Certificat '%s', serial '%s' not found ", commonName, serialNumber))
	}
	log.Printf("unrevoke %v", *cert)

	RestoreCertBySerial(easyrsa, cert.SerialNumber, cert.Username)
	if authByPassword {
		_, _ = shell.RunBash(fmt.Sprintf("openvpn-user restore --db-path %s --user %s", authDatabase, cert.Username))
	}

	(*cert).Flag = "V"
	(*cert).RevocationDate = ""

	err := easyrsa.WriteIndexTxt(all)
	if err != nil {
		log.Printf(err.Error())
		return nil, err
	}
	easyrsa.RebuildClientRevocationList()
	return cert, nil
}

func (easyrsa Easyrsa) RotateServerCert(newDefinition *UserDefinition, cert *IssuedCertificate) (*Certificate, error) {
	log.Printf("rotate server cert %s", cert.CommonName)
	if cert.SerialNumber == nil {
		log.Printf("serialNumber is invalid in %v", cert)
		return nil, errors.New(fmt.Sprintf("serialNumber is invalid in %v", cert))
	}
	//cert, _ := easyrsa.FindUnrevokedCertificate(conf.ServerCert.CommonName)

	//serialStr := fmt.Sprintf("%X", conf.ServerCert.SerialNumber)

	err := easyrsa.RevokeCertificate(cert.CommonName, cert.SerialNumber)
	if err != nil {
		return nil, err
	}
	certificate, err := easyrsa.CreateServerCertificate(*newDefinition)
	if err != nil {
		return nil, err
	}
	log.Printf("server certificate created: %v", certificate)
	log.Printf("generated: %v, expires at %v", certificate.SerialNumber, certificate.ExpirationDate)
	(*cert).Email = certificate.Email
	(*cert).Province = certificate.Province
	(*cert).City = certificate.City
	(*cert).Country = certificate.Country
	(*cert).Organisation = certificate.Organisation
	(*cert).OrganisationUnit = certificate.OrganisationUnit
	(*cert).SerialNumber = HexToBigInt(certificate.SerialNumber)
	(*cert).ExpiresAt = parseDate(stringDateFormat, certificate.ExpirationDate)
	log.Printf("server changed in memory: %v", cert.SerialNumber)
	//log.Printf("imported: %s, expires at %s", bigIntToString(conf.ServerCert.SerialNumber), conf.ServerCert.ExpiresAt)
	//_, err := shell.RunBash(fmt.Sprintf("cd %s && echo yes | %s renew %s nopass", easyrsa.EasyrsaDirPath, easyrsa.EasyrsaBinPath, conf.ServerCert.CommonName))
	//if err != nil {
	//	return errors.New(fmt.Sprintf("Error renewing server certificate \"%s\"", err))
	//}
	return certificate, nil
}

func (easyrsa Easyrsa) RotateClientCert(commonName string, newDefinition *UserDefinition) (*Certificate, error) {
	cert, _ := easyrsa.FindUnrevokedCertificate(commonName)

	if cert != nil {
		err := easyrsa.RevokeCertificate(commonName, HexToBigInt(cert.SerialNumber))
		if err != nil {
			return nil, err
		}
		//return nil, errors.New("certificate " + commonName + " not found")

		//if cert.Flag != "V" {
		//	return nil, errors.New(fmt.Sprintf("Certificate \"%s\" is already revoked", cert.Username))
		//}
		//_, err := shell.RunBash(fmt.Sprintf("cd %s && echo yes | %s revoke %s", easyrsa.EasyrsaDirPath, easyrsa.EasyrsaBinPath, cert.Username))
		//if err != nil {
		//	return nil, errors.New(fmt.Sprintf("Error revoking certificate \"%s\"", err))
		//}
	}

	newDefinition.CommonName = commonName
	newDefinition.Password = ""

	log.Printf("create certificate with %s, expires %v", commonName, newDefinition.ExpiresAt)
	newCert, err := easyrsa.CreateClientCertificate(*newDefinition)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Fail to create certificate for \"%s\": %s", commonName, err))
	}

	//if authByPassword {
	//	shell.RunBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", authDatabase, commonName, newDefinition.Password))
	//}
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

	//easyrsa.WriteIndexTxt(all)
	chmodFix(easyrsa.EasyrsaDirPath)
	return cert, nil
}

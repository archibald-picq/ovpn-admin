package openvpn

import (
	"log"
	"rpiadm/backend/shell"
	"strings"
	"time"
)

type Easyrsa struct {
	EasyrsaBinPath string
	EasyrsaDirPath string
}

func (easyrsa Easyrsa) CheckEasyrsaVersionOrAbsent() string {
	if !shell.FileExist(easyrsa.EasyrsaBinPath) {
		return "absent"
	}
	output, err := shell.RunBash(easyrsa.EasyrsaBinPath + " --version")
	if err != nil {
		return "error"
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Version:") {
			line = strings.TrimSpace(line[len("Version:"):])
			return line
		}
	}
	return "error"
}

func (easyrsa Easyrsa) WriteIndexTxt(all []*Certificate) error {
	err := shell.WriteFile(easyrsa.EasyrsaDirPath+"/pki/index.txt", RenderIndexTxt(all))
	chmodFix(easyrsa.EasyrsaDirPath)
	return err
}

func (easyrsa Easyrsa) PatchRevokedCertificates(all []*Certificate) []*Certificate {
	changed := false
	for _, cert := range all {

		if cert.Flag == "D" {
			//log.Printf("check deleted cert %s", cert.Username)
			certRevoked := ReadIssuedCertificate(easyrsa.EasyrsaDirPath + "/pki/revoked/certs_by_serial/" + cert.SerialNumber + ".crt")
			if certRevoked != nil && certRevoked.CommonName != cert.Username {
				if changed == false {
					log.Printf("  -> index.txt: fix inconsistency")
				}
				log.Printf("      -> deleted cert '%s' (serial: %s) does not match revoked cert '%s'", cert.Username, cert.SerialNumber, certRevoked.CommonName)
				(*cert).Username = certRevoked.CommonName
				changed = true
			}
		}

		if !shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/issued/"+cert.Username+".crt") &&
			shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/revoked/certs_by_serial/"+cert.SerialNumber+".crt") &&
			!shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/private/"+cert.Username+".key") &&
			shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/revoked/private_by_serial/"+cert.SerialNumber+".key") &&
			!shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/reqs/"+cert.Username+".req") &&
			shell.FileExist(easyrsa.EasyrsaDirPath+"/pki/revoked/reqs_by_serial/"+cert.SerialNumber+".req") {

			if cert.Flag == "V" {
				if changed == false {
					log.Printf("  -> index.txt: fix inconsistency")
				}
				log.Printf("      -> cert %s is marked V but all files are revokated")
				(*cert).Flag = "R"
				(*cert).RevocationDate = time.Now().Format(time.RFC3339)
				changed = true
			}
		}

		//if cert.Flag == "R" {
		//	if shell.FileExist() {
		//
		//	}
		//}
	}

	if changed {
		easyrsa.WriteIndexTxt(all)
	}
	return all
}

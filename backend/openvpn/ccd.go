package openvpn

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"rpiadm/backend/shell"
	"strings"
	"text/template"
)

type OpenvpnServer struct {
	Host     string
	Port     string
	Protocol string
}

type OpenvpnClientConfig struct {
	Hosts              []OpenvpnServer
	CA                 string
	Cert               string
	Key                string
	TLS                string
	PasswdAuth         bool
	TlsCrypt           string
	CompLzo            bool
	CertCommonName     string
	ExplicitExitNotify bool
	Auth               string
	AuthNocache        bool
	Cipher             string
	TlsClient          bool
	TlsVersionMin      string
	TlsCipher          string
}

func BuildIndexLine(cert *Certificate) string {
	indexTxt := ""
	///C=FR/ST=Meurthe-et-Moselle/L=Nancy/O=Architech/OU=ROOT-CA/CN=paris/emailAddress=archibald.picq@gmail.com
	identity := ""
	if len(cert.Country) > 0 {
		identity = identity + "/C=" + cert.Country
	}
	if len(cert.Province) > 0 {
		identity = identity + "/ST=" + cert.Province
	}
	if len(cert.City) > 0 {
		identity = identity + "/L=" + cert.City
	}
	if len(cert.Organisation) > 0 {
		identity = identity + "/O=" + cert.Organisation
	}
	if len(cert.OrganisationUnit) > 0 {
		identity = identity + "/OU=" + cert.OrganisationUnit
	}
	if len(cert.Username) > 0 {
		if cert.Flag == "D" {
			identity = identity + "/CN=DELETED-" + cert.Username + "-" + cert.DeletionDate

		} else {
			identity = identity + "/CN=" + cert.Username
		}
	}
	if len(cert.Email) > 0 {
		identity = identity + "/emailAddress=" + cert.Email
	}

	switch {
	case cert.Flag == "V":
		indexTxt += fmt.Sprintf(
			"%s\t%s\t\t%s\t%s\t%s\n",
			cert.Flag,
			parseDate(stringDateFormat, cert.ExpirationDate).Format(indexTxtDateLayout),
			cert.SerialNumber,
			cert.Filename,
			identity,
		)
	case cert.Flag == "R":
		indexTxt += fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			cert.Flag,
			parseDate(stringDateFormat, cert.ExpirationDate).Format(indexTxtDateLayout),
			parseDate(stringDateFormat, cert.RevocationDate).Format(indexTxtDateLayout),
			cert.SerialNumber,
			cert.Filename,
			identity,
		)
	case cert.Flag == "D":
		indexTxt += fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%s\t%s\n",
			cert.Flag,
			parseDate(stringDateFormat, cert.ExpirationDate).Format(indexTxtDateLayout),
			parseDate(stringDateFormat, cert.RevocationDate).Format(indexTxtDateLayout),
			cert.SerialNumber,
			cert.Filename,
			identity,
		)

		// case line.flag == "E":
	}
	return indexTxt
}

//func RenderIndexTxtDevice(data []*model.Device) []byte {
//	indexTxt := ""
//	for _, device := range data {
//		indexTxt += BuildIndexLine(device.Certificate)
//	}
//	return []byte(indexTxt)
//}

func RenderIndexTxt(data []*Certificate) []byte {
	indexTxt := ""
	for _, cert := range data {
		indexTxt += BuildIndexLine(cert)
	}
	return []byte(indexTxt)
}

func ParseCcd(ccdDir string, username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []Route{}
	ccd.CustomIRoutes = []Route{}

	var txtLinesArray []string

	//log.Warnf("reading ccd \"%s\"", *ccdDir + "/" + username)
	if shell.FileExist(ccdDir + "/" + username) {
		txtLinesArray = strings.Split(shell.ReadFile(ccdDir+"/"+username), "\n")
	}

	for _, v := range txtLinesArray {
		parts := strings.SplitN(v, "#", 2)
		//log.Warnf("reading ccd parts [%s]", parts)
		code := parts[0]
		description := ""
		if len(parts) > 1 {
			description = parts[1]
		}
		// log.Warnf("reading ccd line [%s] [%s]", code, description)
		str := strings.Fields(code)
		if len(str) > 0 {
			if strings.HasPrefix(str[0], "ifconfig-push") && len(str) > 1 {
				ccd.ClientAddress = str[1]
			} else if strings.HasPrefix(str[0], "push") && len(str) > 3 {
				ccd.CustomRoutes = append(ccd.CustomRoutes, Route{
					Address:     strings.Trim(str[2], "\""),
					Netmask:     strings.Trim(str[3], "\""),
					Description: strings.Trim(description, " "),
				})
			} else if strings.HasPrefix(str[0], "iroute") && len(str) > 2 {
				ccd.CustomIRoutes = append(ccd.CustomIRoutes, Route{
					Address:     strings.Trim(str[1], "\""),
					Netmask:     strings.Trim(str[2], "\""),
					Description: strings.Trim(description, " "),
				})
			} else {
				log.Printf("ignored ccd line in \"%s\": \"%s\"", username, v)
			}
		}
	}

	return ccd
}

func BuildCcd(ccd Ccd, serverMask string) []byte {

	var lines = make([]string, 0)

	if len(ccd.ClientAddress) > 0 {
		lines = append(lines, fmt.Sprintf("ifconfig-push %s %s", ccd.ClientAddress, serverMask))
	}

	for _, route := range ccd.CustomRoutes {
		desc := ""
		if len(route.Description) > 0 {
			desc = " # " + route.Description
		}
		lines = append(lines, fmt.Sprintf(`push "route %s %s"%s`, route.Address, route.Netmask, desc))
	}

	for _, route := range ccd.CustomIRoutes {
		desc := ""
		if len(route.Description) > 0 {
			desc = " # " + route.Description
		}
		lines = append(lines, fmt.Sprintf(`iroute %s %s%s`, route.Address, route.Netmask, desc))
	}

	return []byte(strings.Join(lines, "\n") + "\n")
}

func UpdateCcd(easyDirPath string, ccdDir string, openvpnNetwork string, serverMask string, ccd Ccd) error {
	err := ValidateCcd(easyDirPath, ccdDir, openvpnNetwork, ccd)
	if err != nil {
		return err
	}
	err = shell.WriteFile(ccdDir+"/"+ccd.User, BuildCcd(ccd, serverMask))
	if err != nil {
		log.Printf("modifyCcd: fWrite(): %v", err)
		return err
	}
	return nil
}

func ValidateCcd(easyDirPath string, ccdDir string, openvpnNetwork string, ccd Ccd) error {
	certs := IndexTxtParserCertificate(shell.ReadFile(easyDirPath + "/pki/index.txt"))
	if ccd.ClientAddress != "dynamic" && len(ccd.ClientAddress) > 0 {
		_, ovpnNet, err := net.ParseCIDR(openvpnNetwork)
		if err != nil {
			return err
		}

		if !checkStaticAddressIsFree(ccdDir, certs, ccd.ClientAddress, ccd.User) {
			return errors.New(fmt.Sprintf("ClientAddress \"%s\" already assigned to another user", ccd.ClientAddress))
		}

		if net.ParseIP(ccd.ClientAddress) == nil {
			return errors.New(fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress))
		}

		if !ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
			return errors.New(fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network \"%s\"", ccd.ClientAddress, ovpnNet))
		}
	}

	for _, route := range ccd.CustomRoutes {
		if net.ParseIP(route.Address) == nil {
			return errors.New(fmt.Sprintf("CustomRoute.Address \"%s\" must be a valid IP address", route.Address))
		}

		if net.ParseIP(route.Netmask) == nil {
			return errors.New(fmt.Sprintf("CustomRoute.Mask \"%s\" must be a valid IP address", route.Netmask))
		}
	}

	return nil
}

func checkStaticAddressIsFree(ccdDir string, certs []*Certificate, staticAddress string, username string) bool {
	for _, client := range certs {
		if client.Username != username {
			ccd := ParseCcd(ccdDir, client.Username)
			if ccd.ClientAddress == staticAddress {
				return false
			}
		}
	}
	return true
}

func RenderClientConfig(
	servers []string,
	config OvpnConfig,
	explicitExitNotify bool,
	authNocache bool,
	address string,
	VerifyX509Name bool,
	outboundIp string,
	masterCn string,
	serverConfFile string,
	easyrsaDirPath string,
	t *template.Template,
	authByPassword bool,
	username string,
) string {
	var hosts []OpenvpnServer
	for _, server := range servers {
		if len(server) > 0 {
			parts := strings.SplitN(server, ":", 3)
			l := len(parts)
			if l > 2 {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1], Protocol: parts[2]})
			} else {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1]})
			}
		}
	}

	if len(hosts) == 0 {
		if len(address) > 0 {
			parts := strings.SplitN(address, ":", 2)
			if len(parts) == 1 {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: fmt.Sprintf("%d", config.Port)})
			} else {
				hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1]})
			}
		} else {
			hosts = append(hosts, OpenvpnServer{Host: outboundIp, Port: fmt.Sprintf("%d", config.Port)})
		}
	}

	//log.Infof("hosts for %s\n %v", username, hosts)

	conf := OpenvpnClientConfig{}
	conf.Hosts = hosts
	conf.CA = shell.ReadFile(easyrsaDirPath + "/pki/ca.crt")
	if _, err := os.Stat(easyrsaDirPath + "/pki/ta.key"); err == nil {
		conf.TLS = shell.ReadFile(easyrsaDirPath + "/pki/ta.key")
	}
	if len(masterCn) > 0 && VerifyX509Name {
		conf.CertCommonName = masterCn
	}
	if config.CompLzo {
		conf.CompLzo = true
	}
	if len(config.TlsCrypt) > 0 {
		conf.TlsCrypt = shell.ReadFile(shell.AbsolutizePath(serverConfFile, config.TlsCrypt))
	}

	conf.Auth = config.Auth
	conf.ExplicitExitNotify = explicitExitNotify
	conf.AuthNocache = authNocache
	conf.Cipher = config.Cipher
	conf.TlsClient = config.TlsServer
	conf.TlsVersionMin = config.TlsVersionMin
	conf.TlsCipher = config.TlsCipher

	conf.Cert = removeCertificatText(shell.ReadFile(easyrsaDirPath + "/pki/issued/" + username + ".crt"))
	conf.Key = shell.ReadFile(easyrsaDirPath + "/pki/private/" + username + ".key")

	conf.PasswdAuth = authByPassword

	var tmp bytes.Buffer
	err := t.Execute(&tmp, conf)
	if err != nil {
		//log.Errorf("something goes wrong during rendering config for %s", username)
		//log.Debugf("rendering config for %s failed with error %v", username, err)
	}

	hosts = nil

	//log.Printf("Rendered config for user %s: %+v", username, tmp.String())

	return fmt.Sprintf("%+v", tmp.String())
}

func removeCertificatText(content string) string {
	lines := strings.Split(content, "\n")
	begin := regexp.MustCompile("-----BEGIN CERTIFICATE-----")
	end := regexp.MustCompile("-----END CERTIFICATE-----")

	output := make([]string, 0)
	isIn := false
	for _, line := range lines {
		if match := begin.FindStringSubmatch(line); len(match) > 0 {
			isIn = true
		}
		if match := end.FindStringSubmatch(line); len(match) > 0 {
			output = append(output, line)
			break
		}
		if isIn {
			output = append(output, line)
		}
	}
	output = append(output, "")
	return strings.Join(output, "\n")
}

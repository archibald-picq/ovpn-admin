package openvpn

import (
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"rpiadm/backend/shell"
	"strings"
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

func buildIndexLine(cert *Certificate) string {
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
			"R",
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

func ExistCcd(serverConf OvpnConfig, commonName string) bool {
	return shell.FileExist(serverConf.CcdDir + "/" + commonName)
}
func RemoveCcd(serverConf OvpnConfig, commonName string) {
	err := shell.DeleteFile(serverConf.CcdDir + "/" + commonName)
	if err != nil {
		log.Printf("deleteFile error: %v", err)
	}
}

func RenderIndexTxt(data []*Certificate) []byte {
	indexTxt := ""
	for _, cert := range data {
		indexTxt += buildIndexLine(cert)
	}
	return []byte(indexTxt)
}

func ParseCcd(serverConf OvpnConfig, username string) *Ccd {
	if !shell.FileExist(serverConf.CcdDir + "/" + username) {
		return nil
	}
	txtLinesArray := strings.Split(shell.ReadFile(serverConf.CcdDir+"/"+username), "\n")
	if len(txtLinesArray) == 0 {
		return nil
	}

	ccd := Ccd{}
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []Route{}
	ccd.CustomIRoutes = []Route{}

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
				log.Printf("ignored ccd line for \"%s\": \"%s\"", username, v)
			}
		}
	}

	return &ccd
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

func UpdateCcd(serverConf OvpnConfig, openvpnNetwork string, serverMask string, ccd Ccd, username string, existingCcd []*Ccd) error {
	err := ValidateCcd(openvpnNetwork, ccd, existingCcd)
	if err != nil {
		return err
	}
	err = shell.WriteFile(serverConf.CcdDir+"/"+username, BuildCcd(ccd, serverMask))
	if err != nil {
		log.Printf("modifyCcd: fWrite(): %v", err)
		return err
	}
	return nil
}

func ValidateCcd(openvpnNetwork string, ccd Ccd, existingCcd []*Ccd) error {
	if ccd.ClientAddress != "dynamic" && len(ccd.ClientAddress) > 0 {
		_, ovpnNet, err := net.ParseCIDR(openvpnNetwork)
		if err != nil {
			return err
		}

		log.Printf("check clientAddress is free %v", ccd.ClientAddress)
		if !checkStaticAddressIsFree(ccd.ClientAddress, existingCcd) {
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

func checkStaticAddressIsFree(staticAddress string, existingCcd []*Ccd) bool {
	for _, existing := range existingCcd {
		if existing.ClientAddress == staticAddress {
			return false
		}
	}
	return true
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

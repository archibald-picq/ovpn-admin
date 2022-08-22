package main

import (
	"bytes"
	"fmt"
	"net"

	"text/template"
	"regexp"
	"strings"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
)

func indexTxtParser(txt string) []OpenvpnClient {
	var indexTxt = make([]OpenvpnClient, 0)
	apochNow := time.Now().Unix()

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			// case strings.HasPrefix(str[0], "E"):

			case strings.HasPrefix(str[0], "V"):
				identity := strings.Join(str[4:], " ")
				//log.Printf("read line for '%s' with flag: %v\n", extractUsername(identity), str[0])
				line := OpenvpnClient{
					Username:       extractUsername(identity),
					flag:           str[0],
					ExpirationDate: parseDateToString(indexTxtDateLayout, str[1], stringDateFormat),
					SerialNumber:   str[2],
					Filename:       str[3],
					Identity:       identity,
					AccountStatus:  "Active",
				}
				line.Country = extractCountry(line.Identity)
				line.Province = extractProvince(line.Identity)
				line.City = extractCity(line.Identity)
				line.Organisation = extractOrganisation(line.Identity)
				line.OrganisationUnit = extractOrganisationUnit(line.Identity)
				line.Email = extractEmail(line.Identity)
				if (parseDateToUnix(stringDateFormat, line.ExpirationDate) - apochNow) < 0 {
					line.AccountStatus = "Expired"
				}
				indexTxt = append(indexTxt, line)
			case strings.HasPrefix(str[0], "R"):
				identity := strings.Join(str[5:], " ")
				//log.Printf("read line for '%s' with flag: %v\n", extractUsername(identity), str[0])
				line := OpenvpnClient{
					Username:       extractUsername(identity),
					flag:           str[0],
					ExpirationDate: parseDateToString(indexTxtDateLayout, str[1], stringDateFormat),
					RevocationDate: parseDateToString(indexTxtDateLayout, str[2], stringDateFormat),
					SerialNumber:   str[3],
					Filename:       str[4],
					Identity:       identity,
					AccountStatus:  "Revoked",
				}
				line.Country = extractCountry(line.Identity)
				line.Province = extractProvince(line.Identity)
				line.City = extractCity(line.Identity)
				line.Organisation = extractOrganisation(line.Identity)
				line.OrganisationUnit = extractOrganisationUnit(line.Identity)
				line.Email = extractEmail(line.Identity)
				if (parseDateToUnix(stringDateFormat, line.ExpirationDate) - apochNow) < 0 {
					line.AccountStatus = "Expired"
				}

				line.DeletionDate = extractDeletionDate(identity)
				if len(line.DeletionDate) > 0 {

					//log.Printf("mark '%s' as DELETED at: %s\n", line.Username, line.DeletionDate)
					line.flag = "D"
				}
				indexTxt = append(indexTxt, line)
			}
		}
	}

	return indexTxt
}

func renderIndexTxt(data []OpenvpnClient) string {
	indexTxt := ""
	for _, line := range data {
		///C=FR/ST=Meurthe-et-Moselle/L=Nancy/O=Architech/OU=ROOT-CA/CN=paris/emailAddress=archibald.picq@gmail.com
		identity := ""
		if len(line.Country) > 0 {
			identity = identity + "/C="+line.Country
		}
		if len(line.Province) > 0 {
			identity = identity + "/ST="+line.Province
		}
		if len(line.City) > 0 {
			identity = identity + "/L="+line.City
		}
		if len(line.Organisation) > 0 {
			identity = identity + "/O="+line.Organisation
		}
		if len(line.OrganisationUnit) > 0 {
			identity = identity + "/OU="+line.OrganisationUnit
		}
		if len(line.Username) > 0 {
			if line.flag == "D" {
				identity = identity + "/CN=DELETED-"+line.Username+"-"+line.DeletionDate

			} else {
				identity = identity + "/CN=" + line.Username
			}
		}
		if len(line.Email) > 0 {
			identity = identity + "/emailAddress="+line.Email
		}

		switch {
		case line.flag == "V":
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", line.flag, parseDate(stringDateFormat, line.ExpirationDate).Format(indexTxtDateLayout), line.SerialNumber, line.Filename, identity)
		case line.flag == "R":
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.flag, parseDate(stringDateFormat, line.ExpirationDate).Format(indexTxtDateLayout), parseDate(stringDateFormat, line.RevocationDate).Format(indexTxtDateLayout), line.SerialNumber, line.Filename, identity)
		case line.flag == "D":
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.flag, parseDate(stringDateFormat, line.ExpirationDate).Format(indexTxtDateLayout), parseDate(stringDateFormat, line.RevocationDate).Format(indexTxtDateLayout), line.SerialNumber, line.Filename, identity)

			// case line.flag == "E":
		}
	}
	return indexTxt
}

func (oAdmin *OvpnAdmin) modifyCcd(ccd Ccd) (bool, string) {
	ccdValid, err := oAdmin.validateCcd(ccd)
	if err != "" {
		return false, err
	}

	if ccdValid {
		t := oAdmin.getCcdTemplate()
		var tmp bytes.Buffer
		err := t.Execute(&tmp, ccd)
		if err != nil {
			log.Error(err)
		}
		if *storageBackend == "kubernetes.secrets" {
			app.secretUpdateCcd(ccd.User, tmp.Bytes())
		} else {
			err = fWrite(*ccdDir+"/"+ccd.User, tmp.String())
			if err != nil {
				log.Errorf("modifyCcd: fWrite(): %v", err)
			}
		}

		return true, "ccd updated successfully"
	}

	return false, "something goes wrong"
}

func (oAdmin *OvpnAdmin) parseCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []Route{}
	ccd.CustomIRoutes = []Route{}

	var txtLinesArray []string
	if *storageBackend == "kubernetes.secrets" {
		txtLinesArray = strings.Split(app.secretGetCcd(ccd.User), "\n")
	} else {
		//log.Warnf("reading ccd \"%s\"", *ccdDir + "/" + username)
		if fExist(*ccdDir + "/" + username) {
			txtLinesArray = strings.Split(fRead(*ccdDir+"/"+username), "\n")
		}
	}

	for _, v := range txtLinesArray {
		parts := strings.SplitN(v, "#", 2)
		log.Warnf("reading ccd parts [%s]", parts)
		code := parts[0]
		description := ""
		if len(parts) > 1 {
			description = parts[1]
		}
		// log.Warnf("reading ccd line [%s] [%s]", code, description)
		str := strings.Fields(code)
		if len(str) > 0 {
			switch {
			case strings.HasPrefix(str[0], "ifconfig-push"):
				ccd.ClientAddress = str[1]
			case strings.HasPrefix(str[0], "push"):
				ccd.CustomRoutes = append(ccd.CustomRoutes, Route{Address: strings.Trim(str[2], "\""), Netmask: strings.Trim(str[3], "\""), Description: strings.Trim(description, " ")})
			case strings.HasPrefix(str[0], "iroute"):
				ccd.CustomIRoutes = append(ccd.CustomIRoutes, Route{Address: strings.Trim(str[1], "\""), Netmask: strings.Trim(str[2], "\""), Description: strings.Trim(description, " ")})
			default:
				log.Warnf("ignored ccd line in \"%s\": \"%s\"", username, v)
			}
		}
	}

	return ccd
}

func (oAdmin *OvpnAdmin) validateCcd(ccd Ccd) (bool, string) {

	ccdErr := ""

	if ccd.ClientAddress != "dynamic" && len(ccd.ClientAddress) > 0 {
		_, ovpnNet, err := net.ParseCIDR(*openvpnNetwork)
		if err != nil {
			log.Error(err)
		}

		if !oAdmin.checkStaticAddressIsFree(ccd.ClientAddress, ccd.User) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" already assigned to another user", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(ccd.ClientAddress) == nil {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if !ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
			ccdErr = fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network \"%s\"", ccd.ClientAddress, ovpnNet)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	for _, route := range ccd.CustomRoutes {
		if net.ParseIP(route.Address) == nil {
			ccdErr = fmt.Sprintf("CustomRoute.Address \"%s\" must be a valid IP address", route.Address)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}

		if net.ParseIP(route.Netmask) == nil {
			ccdErr = fmt.Sprintf("CustomRoute.Mask \"%s\" must be a valid IP address", route.Netmask)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return false, ccdErr
		}
	}

	return true, ccdErr
}

func checkUserActiveExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.Username == username && u.flag == "V" {
			return true
		}
	}
	return false
}

func checkUserExist(username string) (*OpenvpnClient, []OpenvpnClient, error) {
	all := indexTxtParser(fRead(*indexTxtPath))
	for _, u := range all {
		log.Debugf("search username %s match %s", username, u.Username)
		if u.Username == username {
			return &u, all, nil
		}
	}
	return nil, all, errors.New(fmt.Sprint("User %s not found", username))
}

func (oAdmin *OvpnAdmin) getCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []Route{}

	ccd = oAdmin.parseCcd(username)

	return ccd
}

func (oAdmin *OvpnAdmin) checkStaticAddressIsFree(staticAddress string, username string) bool {

	oAdmin.clients = oAdmin.usersList()

	for _, client := range oAdmin.clients {
		if client.Username != username {
			ccd := oAdmin.getCcd(client.Username)
			if ccd.ClientAddress == staticAddress {
				return false
			}
		}
	}
	return true
}

func extractDeletionDate(identity string) string {
	re := regexp.MustCompile("/CN=([^/]+)")
	match := re.FindStringSubmatch(identity)
	if len(match) <= 0 {
		return ""
	}
	if strings.HasPrefix(match[1], "DELETED-") {
		matched := string(match[1][len("DELETED-"):])
		parts := strings.Split(matched, "-")
		return parts[len(parts)-1]
	} else if strings.HasPrefix(match[1], "DELETED") {
		matched := string(match[1][len("DELETED"):])
		parts := strings.Split(matched, "-")
		return parts[len(parts)-1]
	} else {
		return ""
	}
}

func extractCountry(identity string) string {
	re := regexp.MustCompile("/C=([^/]+)")
	match := re.FindStringSubmatch(identity)
	if len(match) <= 0 {
		return ""
	}
	return match[1]
}

func extractCity(identity string) string {
	re := regexp.MustCompile("/L=([^/]+)")
	match := re.FindStringSubmatch(identity)
	if len(match) <= 0 {
		return ""
	}
	return match[1]
}

func extractProvince(identity string) string {
	re := regexp.MustCompile("/ST=([^/]+)")
	match := re.FindStringSubmatch(identity)
	if len(match) <= 0 {
		return ""
	}
	return match[1]
}

func extractOrganisation(identity string) string {
	re := regexp.MustCompile("/O=([^/]+)")
	match := re.FindStringSubmatch(identity)
	if len(match) <= 0 {
		return ""
	}
	return match[1]
}

func extractOrganisationUnit(identity string) string {
	re := regexp.MustCompile("/OU=([^/]+)")
	match := re.FindStringSubmatch(identity)
	if len(match) <= 0 {
		return ""
	}
	return match[1]
}

func extractEmail(identity string) string {
	re := regexp.MustCompile("/emailAddress=([^/]+)")
	match := re.FindStringSubmatch(identity)
	if len(match) <= 0 {
		return ""
	}
	return match[1]
}

func extractUsername(identity string) string {
	re := regexp.MustCompile("/CN=([^/]+)")
	match := re.FindStringSubmatch(identity)
	if len(match) <= 0 {
		return ""
	}
	//if strings.HasPrefix(match[1], "REVOKED") {
	//	matched := string(match[1][len("REVOKED"):])
	//	matched, _, _ = strings.Cut(matched, "-")
	//	return matched
	//} else
	if strings.HasPrefix(match[1], "DELETED-") {
		matched := string(match[1][len("DELETED-"):])
		matched, _, _ = strings.Cut(matched, "-")
		return matched
	} else if strings.HasPrefix(match[1], "DELETED") {
		matched := string(match[1][len("DELETED"):])
		matched, _, _ = strings.Cut(matched, "-")
		return matched
	} else {
		matched := match[1]
		return matched
	}
}

func (oAdmin *OvpnAdmin) getCcdTemplate() *template.Template {
	if *ccdTemplatePath != "" {
		return template.Must(template.ParseFiles(*ccdTemplatePath))
	} else {
		ccdTpl, ccdTplErr := templates.ReadFile("templates/ccd.tpl")
		if ccdTplErr != nil {
			log.Errorf("ccdTpl not found in templates box")
		}
		return template.Must(template.New("ccd").Parse(string(ccdTpl)))
	}
}

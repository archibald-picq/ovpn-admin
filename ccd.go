package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"regexp"
	"strings"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
)

func (app *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	//if app.role == "slave" {
	//	http.Error(w, `{"status":"error"}`, http.StatusLocked)
	//	return
	//}
	var ccd Ccd
	if r.Body == nil {
		json, _ := json.Marshal(MessagePayload{Message: "Please send a request body"})
		http.Error(w, string(json), http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		log.Errorln(err)
	}

	for i, _ := range ccd.CustomRoutes {
		ccd.CustomRoutes[i].Description = strings.Trim(ccd.CustomRoutes[i].Description, " ")
		log.Debugln("description [%v]", ccd.CustomRoutes[i].Description)
	}
	for i, _ := range ccd.CustomIRoutes {
		ccd.CustomIRoutes[i].Description = strings.Trim(ccd.CustomIRoutes[i].Description, " ")
		log.Debugln("description [%v]", ccd.CustomIRoutes[i].Description)
	}

	err = app.modifyCcd(ccd)

	if err == nil {
		w.WriteHeader(http.StatusNoContent)
		fmt.Fprintf(w, fmt.Sprintf("%s", err))
		return
	} else {
		rawJson, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("%s", err)})
		http.Error(w, string(rawJson), http.StatusUnprocessableEntity)
	}
}

func (app *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	//if app.role == "slave" {
	//	http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
	//	return
	//}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != app.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

func indexTxtParser(txt string) []*ClientCertificate {
	var indexTxt = make([]*ClientCertificate, 0)
	//apochNow := time.Now().Unix()

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			// case strings.HasPrefix(str[0], "E"):

			case strings.HasPrefix(str[0], "V"):
				identity := strings.Join(str[4:], " ")
				line := createClientCertificate(identity, str[0], str[1], nil, str[2], str[3])
				indexTxt = append(indexTxt, line)
			case strings.HasPrefix(str[0], "R"):
				identity := strings.Join(str[5:], " ")
				line := createClientCertificate(identity, str[0], str[1], &str[2], str[3], str[4])
				indexTxt = append(indexTxt, line)
			}
		}
	}

	return indexTxt
}

func createClientCertificate(identity string, flag string, expirationDate string, revocationDate *string, serialNumber string, filename string) *ClientCertificate {
	apochNow := time.Now().Unix()
	line := new(ClientCertificate)
	line.Username = extractUsername(identity)
	line.flag = flag
	line.ExpirationDate = parseDateToString(indexTxtDateLayout, expirationDate, stringDateFormat)
	if revocationDate != nil && *revocationDate != "" {
		line.RevocationDate = parseDateToString(indexTxtDateLayout, *revocationDate, stringDateFormat)
	}
	line.SerialNumber = serialNumber
	line.Filename = filename
	line.Identity = identity
	line.AccountStatus = "Active"
	//line.Rpic = make([]*WsSafeConn, 0)
	line.Connections = make([]*VpnClientConnection, 0)
	line.Rpic = make([]*WsRpiConnection, 0)

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
	return line
}

func (app *OvpnAdmin) updateCertificate(certificate *ClientCertificate) {
	for _, existing := range app.clients {
		if existing.Username == certificate.Username {
			existing.flag = certificate.flag
			existing.ExpirationDate = certificate.ExpirationDate
			existing.RevocationDate = certificate.RevocationDate
			existing.SerialNumber = certificate.SerialNumber
			existing.Filename = certificate.Filename
			existing.Identity = certificate.Identity
			existing.AccountStatus = certificate.AccountStatus
			existing.Country = certificate.Country
			existing.Province = certificate.Province
			existing.City = certificate.City
			existing.Organisation = certificate.Organisation
			existing.OrganisationUnit = certificate.OrganisationUnit
			existing.Email = certificate.Email
			existing.DeletionDate = certificate.DeletionDate
			return
		}
	}
	app.clients = append(app.clients, certificate)
}

func renderIndexTxt(data []*ClientCertificate) string {
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

func (app *OvpnAdmin) modifyCcd(ccd Ccd) error {
	err := app.validateCcd(ccd)
	if err != nil {
		return err
	}

	var lines = make([]string, 0)

	if len(ccd.ClientAddress) > 0 {
		lines = append(lines, fmt.Sprintf("ifconfig-push %s 255.255.255.0", ccd.ClientAddress))
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

	ccdContent := strings.Join(lines, "\n")+"\n"
	ccdFile := *ccdDir+"/"+ccd.User
	err = fWrite(ccdFile, ccdContent)
	if err != nil {
		log.Errorf("modifyCcd: fWrite(): %v", err)
	}

	return nil
}

func (app *OvpnAdmin) parseCcd(username string) Ccd {
	ccd := Ccd{}
	ccd.User = username
	ccd.ClientAddress = "dynamic"
	ccd.CustomRoutes = []Route{}
	ccd.CustomIRoutes = []Route{}

	var txtLinesArray []string

	//log.Warnf("reading ccd \"%s\"", *ccdDir + "/" + username)
	if fExist(*ccdDir + "/" + username) {
		txtLinesArray = strings.Split(fRead(*ccdDir+"/"+username), "\n")
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
				log.Warnf("ignored ccd line in \"%s\": \"%s\"", username, v)
			}
		}
	}

	return ccd
}

func (app *OvpnAdmin) validateCcd(ccd Ccd) error {
	if ccd.ClientAddress != "dynamic" && len(ccd.ClientAddress) > 0 {
		_, ovpnNet, err := net.ParseCIDR(*openvpnNetwork)
		if err != nil {
			log.Error(err)
		}

		if !app.checkStaticAddressIsFree(ccd.ClientAddress, ccd.User) {
			ccdErr := fmt.Sprintf("ClientAddress \"%s\" already assigned to another user", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return errors.New(ccdErr)
		}

		if net.ParseIP(ccd.ClientAddress) == nil {
			ccdErr := fmt.Sprintf("ClientAddress \"%s\" not a valid IP address", ccd.ClientAddress)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return errors.New(ccdErr)
		}

		if !ovpnNet.Contains(net.ParseIP(ccd.ClientAddress)) {
			ccdErr := fmt.Sprintf("ClientAddress \"%s\" not belongs to openvpn server network \"%s\"", ccd.ClientAddress, ovpnNet)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return errors.New(ccdErr)
		}
	}

	for _, route := range ccd.CustomRoutes {
		if net.ParseIP(route.Address) == nil {
			ccdErr := fmt.Sprintf("CustomRoute.Address \"%s\" must be a valid IP address", route.Address)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return errors.New(ccdErr)
		}

		if net.ParseIP(route.Netmask) == nil {
			ccdErr := fmt.Sprintf("CustomRoute.Mask \"%s\" must be a valid IP address", route.Netmask)
			log.Debugf("modify ccd for user %s: %s", ccd.User, ccdErr)
			return errors.New(ccdErr)
		}
	}

	return nil
}

func checkUserActiveExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.Username == username && u.flag == "V" {
			return true
		}
	}
	return false
}

func checkUserExist(username string) (*ClientCertificate, []*ClientCertificate, error) {
	all := indexTxtParser(fRead(*indexTxtPath))
	for _, u := range all {
		log.Debugf("search username %s match %s", username, u.Username)
		if u.Username == username {
			return u, all, nil
		}
	}
	return nil, all, errors.New(fmt.Sprint("User %s not found", username))
}

func (app *OvpnAdmin) getCcd(username string) Ccd {
	ccd := Ccd{
		User: username,
		ClientAddress: "dynamic",
		CustomRoutes: []Route{},
	}
	ccd = app.parseCcd(username)
	return ccd
}

func (app *OvpnAdmin) checkStaticAddressIsFree(staticAddress string, username string) bool {
	app.usersList()
	for _, client := range app.clients {
		if client.Username != username {
			ccd := app.getCcd(client.Username)
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


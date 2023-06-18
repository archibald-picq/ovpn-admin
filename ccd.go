package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"text/template"

	"errors"
	"regexp"
	"strings"
	"time"

	"log"
)

func (app *OvpnAdmin) writeIndexTxt(usersFromIndexTxt []*ClientCertificate) error {
	return fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
}

func (app *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var ccd Ccd
	if r.Body == nil {
		json, _ := json.Marshal(MessagePayload{Message: "Please send a request body"})
		http.Error(w, string(json), http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		rawJson, _ := json.Marshal(MessagePayload{Message: "Can't parse JSON body"})
		http.Error(w, string(rawJson), http.StatusInternalServerError)
		return
	}

	for i, _ := range ccd.CustomRoutes {
		ccd.CustomRoutes[i].Description = strings.Trim(ccd.CustomRoutes[i].Description, " ")
	}
	for i, _ := range ccd.CustomIRoutes {
		ccd.CustomIRoutes[i].Description = strings.Trim(ccd.CustomIRoutes[i].Description, " ")
	}

	err = app.modifyCcd(extractNetmask(app.serverConf.server), ccd)

	if err != nil {
		rawJson, _ := json.Marshal(MessagePayload{Message: err.Error()})
		http.Error(w, string(rawJson), http.StatusUnprocessableEntity)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != app.masterSyncToken {
		rawJson, _ := json.Marshal(MessagePayload{Message: "error"})
		http.Error(w, string(rawJson), http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

func indexTxtParser(txt string) []*ClientCertificate {
	var indexTxt = make([]*ClientCertificate, 0)

	txtLinesArray := strings.Split(txt, "\n")
	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) <= 0 {
			continue
		}
		switch {
		case strings.HasPrefix(str[0], "V"):
			identity := strings.Join(str[4:], " ")
			line := createClientCertificate(identity, "V", str[1], nil, str[2], str[3])
			indexTxt = append(indexTxt, line)
		case strings.HasPrefix(str[0], "R"):
			identity := strings.Join(str[5:], " ")
			line := createClientCertificate(identity, "R", str[1], &str[2], str[3], str[4])
			indexTxt = append(indexTxt, line)
		}
	}

	return indexTxt
}

func createClientCertificate(identity string, flag string, expirationDate string, revocationDate *string, serialNumber string, filename string) *ClientCertificate {
	apochNow := time.Now().Unix()
	line := new(ClientCertificate)
	line.Username = extractUsername(identity)
	line.Certificate = new(Certificate)
	line.Certificate.flag = flag
	line.Certificate.ExpirationDate = parseDateToString(indexTxtDateLayout, expirationDate, stringDateFormat)
	if revocationDate != nil && *revocationDate != "" {
		line.Certificate.RevocationDate = parseDateToString(indexTxtDateLayout, *revocationDate, stringDateFormat)
	}
	line.Certificate.SerialNumber = serialNumber
	line.Certificate.Filename = filename
	line.Certificate.Identity = identity
	line.Certificate.AccountStatus = "Active"

	line.Certificate.Country = extractCountry(line.Certificate.Identity)
	line.Certificate.Province = extractProvince(line.Certificate.Identity)
	line.Certificate.City = extractCity(line.Certificate.Identity)
	line.Certificate.Organisation = extractOrganisation(line.Certificate.Identity)
	line.Certificate.OrganisationUnit = extractOrganisationUnit(line.Certificate.Identity)
	line.Certificate.Email = extractEmail(line.Certificate.Identity)
	if (parseDateToUnix(stringDateFormat, line.Certificate.ExpirationDate) - apochNow) < 0 {
		line.Certificate.AccountStatus = "Expired"
	}
	line.Certificate.DeletionDate = extractDeletionDate(identity)
	if len(line.Certificate.DeletionDate) > 0 {

		//log.Printf("mark '%s' as DELETED at: %s\n", line.Username, line.DeletionDate)
		line.Certificate.flag = "D"
	}
	line.Connections = make([]*VpnClientConnection, 0)
	line.Rpic = make([]*WsRpiConnection, 0)
	return line
}

func (app *OvpnAdmin) updateCertificate(certificate *ClientCertificate) {
	for _, existing := range app.clients {
		if existing.Username == certificate.Username {
			existing.Certificate.flag = certificate.Certificate.flag
			existing.Certificate.ExpirationDate = certificate.Certificate.ExpirationDate
			existing.Certificate.RevocationDate = certificate.Certificate.RevocationDate
			existing.Certificate.SerialNumber = certificate.Certificate.SerialNumber
			existing.Certificate.Filename = certificate.Certificate.Filename
			existing.Certificate.Identity = certificate.Certificate.Identity
			existing.Certificate.AccountStatus = certificate.Certificate.AccountStatus
			existing.Certificate.Country = certificate.Certificate.Country
			existing.Certificate.Province = certificate.Certificate.Province
			existing.Certificate.City = certificate.Certificate.City
			existing.Certificate.Organisation = certificate.Certificate.Organisation
			existing.Certificate.OrganisationUnit = certificate.Certificate.OrganisationUnit
			existing.Certificate.Email = certificate.Certificate.Email
			existing.Certificate.DeletionDate = certificate.Certificate.DeletionDate
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
		if len(line.Certificate.Country) > 0 {
			identity = identity + "/C="+line.Certificate.Country
		}
		if len(line.Certificate.Province) > 0 {
			identity = identity + "/ST="+line.Certificate.Province
		}
		if len(line.Certificate.City) > 0 {
			identity = identity + "/L="+line.Certificate.City
		}
		if len(line.Certificate.Organisation) > 0 {
			identity = identity + "/O="+line.Certificate.Organisation
		}
		if len(line.Certificate.OrganisationUnit) > 0 {
			identity = identity + "/OU="+line.Certificate.OrganisationUnit
		}
		if len(line.Username) > 0 {
			if line.Certificate.flag == "D" {
				identity = identity + "/CN=DELETED-"+line.Username+"-"+line.Certificate.DeletionDate

			} else {
				identity = identity + "/CN=" + line.Username
			}
		}
		if len(line.Certificate.Email) > 0 {
			identity = identity + "/emailAddress="+line.Certificate.Email
		}

		switch {
		case line.Certificate.flag == "V":
			indexTxt += fmt.Sprintf(
				"%s\t%s\t\t%s\t%s\t%s\n",
				line.Certificate.flag,
				parseDate(stringDateFormat, line.Certificate.ExpirationDate).Format(indexTxtDateLayout),
				line.Certificate.SerialNumber,
				line.Certificate.Filename,
				identity,
			)
		case line.Certificate.flag == "R":
			indexTxt += fmt.Sprintf(
				"%s\t%s\t%s\t%s\t%s\t%s\n",
				line.Certificate.flag,
				parseDate(stringDateFormat, line.Certificate.ExpirationDate).Format(indexTxtDateLayout),
				parseDate(stringDateFormat, line.Certificate.RevocationDate).Format(indexTxtDateLayout),
				line.Certificate.SerialNumber,
				line.Certificate.Filename,
				identity,
			)
		case line.Certificate.flag == "D":
			indexTxt += fmt.Sprintf(
				"%s\t%s\t%s\t%s\t%s\t%s\n",
				line.Certificate.flag,
				parseDate(stringDateFormat, line.Certificate.ExpirationDate).Format(indexTxtDateLayout),
				parseDate(stringDateFormat, line.Certificate.RevocationDate).Format(indexTxtDateLayout),
				line.Certificate.SerialNumber,
				line.Certificate.Filename,
				identity,
			)

			// case line.flag == "E":
		}
	}
	return indexTxt
}

func (app *OvpnAdmin) modifyCcd(serverMask string, ccd Ccd) error {
	err := app.validateCcd(ccd)
	if err != nil {
		return err
	}

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

	ccdContent := strings.Join(lines, "\n")+"\n"
	ccdFile := *ccdDir+"/"+ccd.User
	err = fWrite(ccdFile, ccdContent)
	if err != nil {
		//log.Errorf("modifyCcd: fWrite(): %v", err)
		return err
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

func (app *OvpnAdmin) validateCcd(ccd Ccd) error {
	if ccd.ClientAddress != "dynamic" && len(ccd.ClientAddress) > 0 {
		_, ovpnNet, err := net.ParseCIDR(*openvpnNetwork)
		if err != nil {
			return err
		}

		if !app.checkStaticAddressIsFree(ccd.ClientAddress, ccd.User) {
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

func checkUserActiveExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.Username == username && u.Certificate.flag == "V" {
			return true
		}
	}
	return false
}

func checkUserExist(username string) (*ClientCertificate, []*ClientCertificate, error) {
	all := indexTxtParser(fRead(*indexTxtPath))
	for _, u := range all {
		if u.Username == username {
			return u, all, nil
		}
	}
	return nil, all, errors.New(fmt.Sprintf("User %s not found", username))
}

func (app *OvpnAdmin) updateClientList(clients []*ClientCertificate) {
	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()

	for _, line := range clients {
		if line.Username != app.masterCn && line.Certificate.flag != "D" {
			totalCerts += 1
			switch {
			case line.Certificate.flag == "V":
				validCerts += 1
			case line.Certificate.flag == "R":
				revokedCerts += 1
			case line.Certificate.flag == "E":
				expiredCerts += 1
			}

			ovpnClientCertificateExpire.WithLabelValues(line.Certificate.Identity).Set(float64((parseDateToUnix(stringDateFormat, line.Certificate.ExpirationDate) - apochNow) / 3600 / 24))
			//app.clients = append(app.clients, line)
			app.updateCertificate(line)

		} else {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(stringDateFormat, line.Certificate.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	//app.updateConnections()

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Printf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))
}

func (app *OvpnAdmin) updateConnection(co *VpnClientConnection, conn *VpnClientConnection) {
	co.ConnectedSince = conn.ConnectedSince
	co.RealAddress = conn.RealAddress
	co.SpeedBytesReceived = conn.SpeedBytesReceived
	co.SpeedBytesSent = conn.SpeedBytesSent
	co.BytesReceived = conn.BytesReceived
	co.BytesSent = conn.BytesSent
}

func (app *OvpnAdmin) synchroConnections(conns []*VpnClientConnection) {
	for _, client := range app.clients {
		client.Connections = make([]*VpnClientConnection, 0)
	}
	for _, conn := range conns {
		var found = false
		for _, client := range app.clients {
			if client.Username == conn.commonName {
				client.Connections = append(client.Connections, conn)
				found = true
			}
		}
		if !found {
			log.Printf("Can't find certificate for connection %s", conn.commonName)
		}
	}
}

func (app *OvpnAdmin) getCertificate(username string) *ClientCertificate {
	for _, connectedUser := range app.clients {
		if connectedUser.Username == username {
			return connectedUser
		}
	}
	return nil
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
	app.updateClientList(indexTxtParser(fRead(*indexTxtPath)))
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

func (app *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTpl, clientConfigTplErr := templates.ReadFile("templates/client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Printf("clientConfigTpl not found in templates box")
		}
		return template.Must(template.New("client-config").Parse(string(clientConfigTpl)))
	}
}


func validateUsername(username string) bool {
	var validUsername = regexp.MustCompile(usernameRegexp)
	return validUsername.MatchString(username)
}

func validatePassword(password string) bool {
	if len(password) < passwordMinLength {
		return false
	} else {
		return true
	}
}

func (app *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	ccd, _ := json.Marshal(app.getCcd(r.FormValue("username")))
	fmt.Fprintf(w, "%s", ccd)
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


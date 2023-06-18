package main

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alessio/shellescape.v1"
	"os"
	"strings"
	"time"
)

type UserDefinition struct {
	//Account
	Username         string `json:"username"`
	Password         string `json:"password"`
	Email            string `json:"email"`
	Country          string `json:"country"`
	Province         string `json:"province"`
	City             string `json:"city"`
	Organisation     string `json:"organisation"`
	OrganisationUnit string `json:"organisationUnit"`
}

type VpnClientConnection struct {
	ClientId                int64      `json:"clientId"`
	commonName              string
	RealAddress             string     `json:"realAddress"`
	BytesReceived           int64      `json:"bytesReceived"`
	BytesSent               int64      `json:"bytesSent"`
	SpeedBytesReceived      int64      `json:"speedBytesReceived"`
	SpeedBytesSent          int64      `json:"speedBytesSent"`
	lastByteReceived        time.Time
	ConnectedSince          *string    `json:"connectedSince"`
	VirtualAddress          *string    `json:"virtualAddress"`
	VirtualAddressIPv6      *string    `json:"virtualAddressIPv6"`
	LastRef                 *string    `json:"lastRef"`
	Nodes                   []NodeInfo `json:"nodes"`
	Networks                []Network  `json:"networks"`
}

type Network struct {
	Address  string `json:"address"`
	Netmask  string `json:"netmask"`
	LastSeen string `json:"lastSeen"`
}

type NodeInfo struct {
	Address  string `json:"address"`
	LastSeen string `json:"lastSeen"`
}

func (app *OvpnAdmin) userCreateCertificate(definition UserDefinition) error {

	if !validateUsername(definition.Username) {
		return errors.New(fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", definition.Username, usernameRegexp))
	}

	if checkUserActiveExist(definition.Username) {
		return errors.New(fmt.Sprintf("User \"%s\" already exists", definition.Username))
	}

	if *authByPassword && !validatePassword(definition.Password) {
		return errors.New(fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength))
	}

	o, err := runBash(fmt.Sprintf(
		"cd %s && EASYRSA_REQ_COUNTRY=%s EASYRSA_REQ_PROVINCE=%s EASYRSA_REQ_CITY=%s EASYRSA_REQ_ORG=%s EASYRSA_REQ_OU=%s EASYRSA_REQ_EMAIL=%s ./easyrsa build-client-full %s nopass 1>/dev/null",
		shellescape.Quote(*easyrsaDirPath),
		shellescape.Quote(definition.Country),
		shellescape.Quote(definition.Province),
		shellescape.Quote(definition.City),
		shellescape.Quote(definition.Organisation),
		shellescape.Quote(definition.OrganisationUnit),
		shellescape.Quote(definition.Email),
		shellescape.Quote(definition.Username),
	))
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating certificate \"%s\"", err))
	}

	log.Printf("cert generated %s", o)

	if *authByPassword {
		o, err := runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, definition.Username, definition.Password))
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating user in DB \"%s\"", err))
		}
		log.Debug(o)
	}

	log.Printf("Certificate for user %s issued", definition.Username)

	return nil
}

// WARN: highly risky
func (app *OvpnAdmin) userChangePassword(username, password string) error {
	_, _, err := checkUserExist(username)
	if err != nil {
		return errors.New("User does not exist")
	}
	o, _ := runBash(fmt.Sprintf("openvpn-user check --db.path %s --user %s | grep %s | wc -l", *authDatabase, username, username))
	log.Info(o)

	if !validatePassword(password) {
		return errors.New(fmt.Sprintf("Password for too short, password length must be greater or equal %d", passwordMinLength))
	}

	if strings.TrimSpace(o) == "0" {
		log.Debug("Creating user in users.db")
		o, err = runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, username, password))
		log.Debug(o)
		if err != nil {
			return err
		}
	}

	o, err = runBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", *authDatabase, username, password))
	if err != nil {
		return err
	}
	log.Debug(o)
	//log.Printf("Password for user %s was changed", username)

	return nil
}

func (app *OvpnAdmin) userRevoke(username string) error {
	log.Printf("Revoke certificate for user %s", username)
	client, allClients, err := checkUserExist(username)
	var shellOut string
	if err != nil {
		return errors.New(fmt.Sprintf("User \"%s\" not found", username))
	}

	log.Printf("revoke cert \"%s\" ", username)
	shellOut, err = runBash(fmt.Sprintf("cd %s && echo yes | ./easyrsa revoke %s", *easyrsaDirPath, username))
	if err != nil {
		return errors.New(fmt.Sprintf("Error revoking certificate \"%s\"", err))
	}
	log.Printf(shellOut)

	if *authByPassword {
		shellOut, err := runBash(fmt.Sprintf("openvpn-user revoke --db-path %s --user %s", *authDatabase, username))
		if err != nil {
			return errors.New(fmt.Sprintf("Error updateing DB \"%s\"", err))
		}
		log.Trace(shellOut)
	}

	(*client).Certificate.flag = "R"
	chmodFix()
	app.updateClientList(allClients)
	app.rebuildClientRevocationList()
	user := app.getCertificate(username)

	if user != nil {
		if len(user.Connections) > 0 {
			log.Tracef("User %s connected: %d", username, len(user.Connections))
			app.killUserConnections(user)
		} else {
			log.Tracef("User %s not connected: %d")
		}
	}

	return nil
}

func (app *OvpnAdmin) userUnrevoke(username string) error {
	client, usersFromIndexTxt, err := checkUserExist(username)

	if err != nil {
		return errors.New(fmt.Sprintf("User \"%s\" not found", username))
	}

	log.Printf("unrevoke %v", (*client).Certificate)

	if (*client).Certificate.flag != "R" {
		return errors.New(fmt.Sprintf("Certificate %s is not in revocated state (is %s)", username, (*client).Certificate.flag))
	}

	app.restoreCertBySerial(client.Certificate.SerialNumber, client.Username)
	if *authByPassword {
		_, _ = runBash(fmt.Sprintf("openvpn-user restore --db-path %s --user %s", *authDatabase, username))
	}

	(*client).Certificate.flag = "V"
	err = app.writeIndexTxt(usersFromIndexTxt)
	chmodFix()
	if err != nil {
		log.Error(err)
	}
	app.rebuildClientRevocationList()
	app.updateClientList(usersFromIndexTxt)
	return nil
}

func (app *OvpnAdmin) restoreCertBySerial(serial string, cn string) error {

	app.copyCertFile(
		fmt.Sprintf("pki/revoked/certs_by_serial/%s.crt", serial),
		fmt.Sprintf("pki/issued/%s.crt", cn),
	)

	app.copyCertFile(
		fmt.Sprintf("pki/revoked/certs_by_serial/%s.crt", serial),
		fmt.Sprintf("pki/certs_by_serial/%s.pem", serial),
	)

	app.copyCertFile(
		fmt.Sprintf("pki/revoked/private_by_serial/%s.key", serial),
		fmt.Sprintf("pki/private/%s.key", cn),
	)

	app.copyCertFile(
		fmt.Sprintf("pki/revoked/reqs_by_serial/%s.req", serial),
		fmt.Sprintf("pki/reqs/%s.req", cn),
	)

	if app.fExistsPki(fmt.Sprintf("pki/issued/%s.crt", cn)) && app.fExistsPki(fmt.Sprintf("pki/certs_by_serial/%s.pem", serial)) {
		os.Remove(*easyrsaDirPath + fmt.Sprintf("pki/revoked/certs_by_serial/%s.crt", serial))
	}
	if app.fExistsPki(fmt.Sprintf("pki/private/%s.key", cn)) {
		os.Remove(*easyrsaDirPath + fmt.Sprintf("pki/revoked/private_by_serial/%s.key", serial))
	}
	if app.fExistsPki(fmt.Sprintf("pki/reqs/%s.req", cn)) {
		os.Remove(*easyrsaDirPath + fmt.Sprintf("pki/revoked/reqs_by_serial/%s.req", serial))
	}
	return nil
}

func (app *OvpnAdmin) fExistsPki(f string) bool {
	return fExist(*easyrsaDirPath)
}

func (app *OvpnAdmin) copyCertFile(from string, to string) error {
	if !fExist(*easyrsaDirPath+from) {
		log.Printf("source file %s does not exists", *easyrsaDirPath+from)
		return nil
	}
	if fExist(*easyrsaDirPath+to) {
		log.Printf("target file %s already exists", *easyrsaDirPath+to)
		return nil
	}

	err := fCopy(*easyrsaDirPath+from, *easyrsaDirPath+to)
	if err == nil {
		log.Printf("Moved %s to %s", from, to)
	}
	return err
}

func (app *OvpnAdmin) userRotate(username string, newPassword string) error {
	userFromIndexTxt, usersFromIndexTxt, err := checkUserExist(username)
	if err != nil {
		return errors.New(fmt.Sprintf("User \"%s\" not found\"", username))
	}

	if userFromIndexTxt.Certificate.flag != "V" {
		return errors.New(fmt.Sprintf("Certificate \"%s\" is already revoked", userFromIndexTxt.Username))
	}
	_, err = runBash(fmt.Sprintf("cd %s && echo yes | ./easyrsa revoke %s", *easyrsaDirPath, userFromIndexTxt.Username))
	if err != nil {
		return errors.New(fmt.Sprintf("Error revoking certificate \"%s\"", err))
	}
	app.rebuildClientRevocationList()
	chmodFix()

	err = app.userCreateCertificate(UserDefinition{
		Username: userFromIndexTxt.Username,
		Password: newPassword,
		City: userFromIndexTxt.Certificate.City,
		Province: userFromIndexTxt.Certificate.Province,
		Country: userFromIndexTxt.Certificate.Country,
		Organisation: userFromIndexTxt.Certificate.Organisation,
		OrganisationUnit: userFromIndexTxt.Certificate.OrganisationUnit,
		Email: userFromIndexTxt.Certificate.Email,
	})
	if err != nil {
		return errors.New(fmt.Sprintf("Fail to create certificate for \"%s\": %s", userFromIndexTxt.Username, err))
	}

	if *authByPassword {
		runBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", *authDatabase, username, newPassword))
	}


	app.writeIndexTxt(usersFromIndexTxt)
	app.updateClientList(usersFromIndexTxt)
	return nil
}

func (app *OvpnAdmin) userDelete(username string) string {
	client, usersFromIndexTxt, err := checkUserExist(username)
	if err != nil {
		return fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}

	uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
	//usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
	if client != nil {
		(*client).Username = "DELETED-" + username + "-" + uniqHash
		app.writeIndexTxt(usersFromIndexTxt)
		app.rebuildClientRevocationList()
	}

	chmodFix()
	app.updateClientList(usersFromIndexTxt)
	return fmt.Sprintf("{\"msg\":\"User %s successfully deleted\"}", username)
}

func (app *OvpnAdmin) rebuildClientRevocationList() {
	log.Printf("rebuild CRL")
	_, err := runBash(fmt.Sprintf("cd %s && ./easyrsa gen-crl", *easyrsaDirPath))
	if err != nil {
		log.Printf("fail to rebuild crl", err)
	}
}

func archiveCerts() {
	err := createArchiveFromDir(*easyrsaDirPath+"/pki", certsArchivePath)
	if err != nil {
		log.Warnf("archiveCerts(): %s", err)
	}
}

func archiveCcd() {
	err := createArchiveFromDir(*ccdDir, ccdArchivePath)
	if err != nil {
		log.Warnf("archiveCcd(): %s", err)
	}
}

//func unArchiveCerts() {
//	if err := os.MkdirAll(*easyrsaDirPath+"/pki", 0755); err != nil {
//		log.Warnf("unArchiveCerts(): error creating pki dir: %s", err)
//	}
//
//	err := extractFromArchive(certsArchivePath, *easyrsaDirPath+"/pki")
//	if err != nil {
//		log.Warnf("unArchiveCerts: extractFromArchive() %s", err)
//	}
//}
//
//func unArchiveCcd() {
//	if err := os.MkdirAll(*ccdDir, 0755); err != nil {
//		log.Warnf("unArchiveCcd(): error creating ccd dir: %s", err)
//	}
//
//	err := extractFromArchive(ccdArchivePath, *ccdDir)
//	if err != nil {
//		log.Warnf("unArchiveCcd: extractFromArchive() %s", err)
//	}
//}

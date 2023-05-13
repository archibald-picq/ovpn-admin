package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	log "github.com/sirupsen/logrus"
	"github.com/google/uuid"
	"gopkg.in/alessio/shellescape.v1"
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

func (app *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		json, _ := json.Marshal(MessagePayload{Message: "User not authorized to create certificate"})
		http.Error(w, string(json), http.StatusUnauthorized)
		//w.WriteHeader(http.StatusForbidden)
		return
	}
	var userDefinition UserDefinition
	err := json.NewDecoder(r.Body).Decode(&userDefinition)
	if err != nil {
		jsonErr, _ := json.Marshal(MessagePayload{Message: "Cant parse JSON"})
		http.Error(w, string(jsonErr), http.StatusUnprocessableEntity)
		return
	}
	log.Printf("create user with %v\n", userDefinition)
	userCreated, userCreateStatus := app.userCreate(userDefinition)

	if userCreated {
		user, _, _ := checkUserExist(userDefinition.Username)
		log.Printf("created user with %v\n", user)
		jsonErr, _ := json.Marshal(user)
		w.Write(jsonErr)
		return
	} else {
		jsonErr, _ := json.Marshal(MessagePayload{Message: userCreateStatus})
		http.Error(w, string(jsonErr), http.StatusUnprocessableEntity)
	}
}

func (app *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
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
	_ = r.ParseForm()
	username := r.FormValue("username")
	_, err := app.userRotate(username, r.FormValue("password"))
	if len(err) > 0 {
		http.Error(w, err, http.StatusUnprocessableEntity)
	}
	fmt.Sprintf(`{"message":"User %s successfully rotated"}`, username)
}

func (app *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
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
	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", app.userDelete(r.FormValue("username")))
}

func (app *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
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
	_ = r.ParseForm()
	ret, _ := app.userRevoke(r.FormValue("username"))
	fmt.Fprintf(w, "%s", ret)
}

func (app *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
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

	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", app.userUnrevoke(r.FormValue("username")))
}

func (app *OvpnAdmin) userCreate(definition UserDefinition) (bool, string) {
	var ucErr string


	if !validateUsername(definition.Username) {
		ucErr = fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", definition.Username, usernameRegexp)
		log.Debugf("userCreate: checkUserExist():  %s", ucErr)
		return false, ucErr
	}

	if checkUserActiveExist(definition.Username) {
		ucErr = fmt.Sprintf("User \"%s\" already exists", definition.Username)
		log.Debugf("userCreate: validateUsername(): %s", ucErr)
		return false, ucErr
	}

	if *authByPassword {
		if !validatePassword(definition.Password) {
			ucErr = fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength)
			log.Debugf("userCreate: authByPassword(): %s", ucErr)
			return false, ucErr
		}
	}

	//app.createUserMutex.Lock()
	//defer app.createUserMutex.Unlock()
	//app.createUserMutex.Lock()
	//defer app.createUserMutex.Unlock()


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
		return false, fmt.Sprintf("Error creating certificate \"%s\"", err)
	}

	log.Debug(o)

	if *authByPassword {
		o, err := runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, definition.Username, definition.Password))
		if err != nil {
			return false, fmt.Sprintf("Error creating user in DB \"%s\"", err)
		}
		log.Debug(o)
	}

	log.Infof("Certificate for user %s issued", definition.Username)

	//app.clients = app.usersList()
	return true, ucErr
}

// WARN: highly risky
func (app *OvpnAdmin) userChangePassword(username, password string) (bool, string) {
	_, _, err := checkUserExist(username)
	if err != nil {
		return false, "User does not exist"
	}
	o, _ := runBash(fmt.Sprintf("openvpn-user check --db.path %s --user %s | grep %s | wc -l", *authDatabase, username, username))
	log.Info(o)

	if !validatePassword(password) {
		ucpErr := fmt.Sprintf("Password for too short, password length must be greater or equal %d", passwordMinLength)
		log.Debugf("userChangePassword: %s", ucpErr)
		return false, ucpErr
	}

	if strings.TrimSpace(o) == "0" {
		log.Debug("Creating user in users.db")
		o, _ = runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, username, password))
		log.Debug(o)
	}

	o, _ = runBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", *authDatabase, username, password))
	log.Debug(o)
	log.Infof("Password for user %s was changed", username)

	return true, "Password changed"
}

func (app *OvpnAdmin) userRevoke(username string) (string, string) {
	log.Infof("Revoke certificate for user %s", username)
	_, _, err := checkUserExist(username)
	var shellOut string
	if err != nil {
		log.Infof("user \"%s\" not found", username)
		return "", fmt.Sprintf("User \"%s\" not found", username)
	}
	// check certificate valid flag 'V'

	log.Infof("revoke cert \"%s\" ", username)
	shellOut, err = runBash(fmt.Sprintf("cd %s && echo yes | ./easyrsa revoke %s && ./easyrsa gen-crl", *easyrsaDirPath, username))
	if err != nil {
		return "", fmt.Sprintf("Error revoking certificate \"%s\"", err)
	}
	log.Infof(shellOut)

	if *authByPassword {
		shellOut, err := runBash(fmt.Sprintf("openvpn-user revoke --db-path %s --user %s", *authDatabase, username))
		if err != nil {
			return "", fmt.Sprintf("Error updateing DB \"%s\"", err)
		}
		log.Trace(shellOut)
	}

	//for i, _ := range usersFromIndexTxt {
	//	if usersFromIndexTxt[i].Username == username {
	//		usersFromIndexTxt[i].flag = "R"
	//		fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
	//		break
	//	}
	//}

	chmodFix()
	user := app.getCertificate(username)
	//userConnectedTo := getUserConnections(username, app.activeClients)
	if user != nil {
		if len(user.Connections) > 0 {
			log.Tracef("User %s connected: %d", username, len(user.Connections))
			app.killUserConnections(user)
		} else {
			log.Tracef("User %s not connected: %d")
		}
	}
	//if len(userConnectedTo) > 0 {
	//	for _, connection := range userConnectedTo {
	//		app.killConnection(connection)
	//		log.Infof("Session for user \"%s\" killed", username)
	//	}
	//}

	return fmt.Sprintln(shellOut), ""
}

func (app *OvpnAdmin) userUnrevoke(username string) string {
	userFromIndexTxt, usersFromIndexTxt, err := checkUserExist(username)

	if err != nil {
		return fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}

	if (*userFromIndexTxt).flag == "R" {

		err := fCopy(fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *easyrsaDirPath, (*userFromIndexTxt).SerialNumber), fmt.Sprintf("%s/pki/issued/%s.crt", *easyrsaDirPath, username))
		if err != nil {
			log.Error(err)
		}
		err = fCopy(fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *easyrsaDirPath, (*userFromIndexTxt).SerialNumber), fmt.Sprintf("%s/pki/certs_by_serial/%s.pem", *easyrsaDirPath, (*userFromIndexTxt).SerialNumber))
		if err != nil {
			log.Error(err)
		}
		err = fCopy(fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", *easyrsaDirPath, (*userFromIndexTxt).SerialNumber), fmt.Sprintf("%s/pki/private/%s.key", *easyrsaDirPath, username))
		if err != nil {
			log.Error(err)
		}
		err = fCopy(fmt.Sprintf("%s/pki/revoked/reqs_by_serial/%s.req", *easyrsaDirPath, (*userFromIndexTxt).SerialNumber), fmt.Sprintf("%s/pki/reqs/%s.req", *easyrsaDirPath, username))
		if err != nil {
			log.Error(err)
		}
		err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
		if err != nil {
			log.Error(err)
		}

		runBash(fmt.Sprintf("cd %s && ./easyrsa gen-crl 1>/dev/null", *easyrsaDirPath))

		ret, _ := runBash(fmt.Sprintf("cd %s && ./easyrsa gen-crl", *easyrsaDirPath))
		fmt.Printf("gen-crl %s", ret)

		if *authByPassword {
			_, _ = runBash(fmt.Sprintf("openvpn-user restore --db-path %s --user %s", *authDatabase, username))
		}

		chmodFix()

		//break
		//fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
	} else {
		log.Infof("User \"%s\" already active", userFromIndexTxt.Username)
	}
	chmodFix()
	app.usersList()
	return fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
}

func (app *OvpnAdmin) userRotate(username, newPassword string) (bool, string) {
	userFromIndexTxt, usersFromIndexTxt, err := checkUserExist(username)
	if err != nil {
		return false, fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}

	//uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
	if userFromIndexTxt.flag == "V" {
		_, err := runBash(fmt.Sprintf("cd %s && echo yes | ./easyrsa revoke %s && ./easyrsa gen-crl", *easyrsaDirPath, userFromIndexTxt.Username))
		if err != nil {
			return false, fmt.Sprintf("Error revoking certificate \"%s\"", err)
		}
	} else {
		log.Infof("Skip revoke \"%s\" because it is already revoked", userFromIndexTxt.Username)
	}

	definition := UserDefinition{
		Username: userFromIndexTxt.Username,
		Password: newPassword,
		City: userFromIndexTxt.City,
		Province: userFromIndexTxt.Province,
		Country: userFromIndexTxt.Country,
		Organisation: userFromIndexTxt.Organisation,
		OrganisationUnit: userFromIndexTxt.OrganisationUnit,
		Email: userFromIndexTxt.Email,
	}
	_, errMsg := app.userCreate(definition)
	if len(errMsg) > 0 {
		return false, fmt.Sprintf("Fail to create certificate for \"%s\": %s", userFromIndexTxt.Username, err)
	}

	if *authByPassword {
		runBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", *authDatabase, username, newPassword))
	}

	fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))

	runBash(fmt.Sprintf("cd %s && ./easyrsa gen-crl 1>/dev/null", *easyrsaDirPath))
	app.usersList()
	chmodFix()
	return true, fmt.Sprintf("{\"msg\":\"User %s successfully rotated\"}", username)
}

func (app *OvpnAdmin) userDelete(username string) string {
	_, usersFromIndexTxt, err := checkUserExist(username)
	if err != nil {
		return fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}

	uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
	//usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
	for i, _ := range usersFromIndexTxt {
		if usersFromIndexTxt[i].Username == username {
			usersFromIndexTxt[i].Username = "DELETED-" + username + "-" + uniqHash
			fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			break
		}
	}
	_, _ = runBash(fmt.Sprintf("cd %s && ./easyrsa gen-crl", *easyrsaDirPath))
	chmodFix()
	app.usersList()
	return fmt.Sprintf("{\"msg\":\"User %s successfully deleted\"}", username)
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

func unArchiveCerts() {
	if err := os.MkdirAll(*easyrsaDirPath+"/pki", 0755); err != nil {
		log.Warnf("unArchiveCerts(): error creating pki dir: %s", err)
	}

	err := extractFromArchive(certsArchivePath, *easyrsaDirPath+"/pki")
	if err != nil {
		log.Warnf("unArchiveCerts: extractFromArchive() %s", err)
	}
}

func unArchiveCcd() {
	if err := os.MkdirAll(*ccdDir, 0755); err != nil {
		log.Warnf("unArchiveCcd(): error creating ccd dir: %s", err)
	}

	err := extractFromArchive(ccdArchivePath, *ccdDir)
	if err != nil {
		log.Warnf("unArchiveCcd: extractFromArchive() %s", err)
	}
}

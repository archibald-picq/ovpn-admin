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

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
		json, _ := json.Marshal(MessagePayload{Message: "User not authorized to create certificate"})
		http.Error(w, string(json), http.StatusUnauthorized)
		//w.WriteHeader(http.StatusForbidden)
		return
	}
	if oAdmin.role == "slave" {
		json, _ := json.Marshal(MessagePayload{Message: "This instance is a slave, cant process"})
		http.Error(w, string(json), http.StatusLocked)
		return
	}
	var userDefinition UserDefinition
	err := json.NewDecoder(r.Body).Decode(&userDefinition)
	if err != nil {
		json, _ := json.Marshal(MessagePayload{Message: "Cant parse JSON"})
		http.Error(w, string(json), http.StatusUnprocessableEntity)
		return
	}
	//_ = r.ParseForm()
	log.Printf("create user with %v\n", userDefinition)
	userCreated, userCreateStatus := oAdmin.userCreate(userDefinition)

	if userCreated {
		//oAdmin.clients = oAdmin.usersList()
		user, _, _ := checkUserExist(userDefinition.Username)
		log.Printf("created user with %v\n", user)
		json, _ := json.Marshal(user)
		w.Write(json)
		//fmt.Fprintf(w, string(json))
		return
	} else {
		json, _ := json.Marshal(MessagePayload{Message: userCreateStatus})
		http.Error(w, string(json), http.StatusUnprocessableEntity)
	}
}

func (oAdmin *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	username := r.FormValue("username")
	_, err := oAdmin.userRotate(username, r.FormValue("password"))
	if len(err) > 0 {
		http.Error(w, err, http.StatusUnprocessableEntity)
	}
	fmt.Sprintf(`{"message":"User %s successfully rotated"}`, username)
}

func (oAdmin *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.userDelete(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	ret, _ := oAdmin.userRevoke(r.FormValue("username"))
	fmt.Fprintf(w, "%s", ret)
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}

	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.userUnrevoke(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) userCreate(definition UserDefinition) (bool, string) {
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

	//oAdmin.createUserMutex.Lock()
	//defer oAdmin.createUserMutex.Unlock()
	//oAdmin.createUserMutex.Lock()
	//defer oAdmin.createUserMutex.Unlock()

	if *storageBackend == "kubernetes.secrets" {
		err := app.easyrsaBuildClient(definition.Username)
		if err != nil {
			log.Error(err)
		}
	} else {
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
	}

	if *authByPassword {
		o, err := runBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", *authDatabase, definition.Username, definition.Password))
		if err != nil {
			return false, fmt.Sprintf("Error creating user in DB \"%s\"", err)
		}
		log.Debug(o)
	}

	log.Infof("Certificate for user %s issued", definition.Username)

	//oAdmin.clients = oAdmin.usersList()
	return true, ucErr
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (bool, string) {
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

func (oAdmin *OvpnAdmin) userRevoke(username string) (string, string) {
	log.Infof("Revoke certificate for user %s", username)
	_, _, err := checkUserExist(username)
	var shellOut string
	if err != nil {
		log.Infof("user \"%s\" not found", username)
		return "", fmt.Sprintf("User \"%s\" not found", username)
	}
	// check certificate valid flag 'V'
	if *storageBackend == "kubernetes.secrets" {
		err := app.easyrsaRevoke(username)
		if err != nil {
			log.Error(err)
		}
	} else {
		log.Infof("revoke cert \"%s\" ", username)
		shellOut, err := runBash(fmt.Sprintf("cd %s && echo yes | ./easyrsa revoke %s && ./easyrsa gen-crl", *easyrsaDirPath, username))
		if err != nil {
			return "", fmt.Sprintf("Error revoking certificate \"%s\"", err)
		}
		log.Infof(shellOut)
	}

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
	userConnected, userConnectedTo := isUserConnected(username, oAdmin.activeClients)
	log.Tracef("User %s connected: %t", username, userConnected)
	if userConnected {
		for _, connection := range userConnectedTo {
			oAdmin.mgmtKillUserConnection(connection)
			log.Infof("Session for user \"%s\" killed", username)
		}
	}

	return fmt.Sprintln(shellOut), ""
}

func (oAdmin *OvpnAdmin) userUnrevoke(username string) string {
	userFromIndexTxt, usersFromIndexTxt, err := checkUserExist(username)

	if err != nil {
		return fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}
	if *storageBackend == "kubernetes.secrets" {
		err := app.easyrsaUnrevoke(username)
		if err != nil {
			log.Error(err)
		}
	} else {
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
	}
	chmodFix()
	oAdmin.clients = oAdmin.usersList()
	return fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
}

func (oAdmin *OvpnAdmin) userRotate(username, newPassword string) (bool, string) {
	userFromIndexTxt, usersFromIndexTxt, err := checkUserExist(username)
	if err != nil {
		return false, fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}
	if *storageBackend == "kubernetes.secrets" {
		err := app.easyrsaRotate(username, newPassword)
		if err != nil {
			log.Error(err)
		}
	} else {

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
		_, err := oAdmin.userCreate(definition)
		if len(err) > 0 {
			return false, fmt.Sprintf("Fail to create certificate for \"%s\": %s", userFromIndexTxt.Username, err)
		}

		if *authByPassword {
			runBash(fmt.Sprintf("openvpn-user change-password --db.path %s --user %s --password %s", *authDatabase, username, newPassword))
		}

		fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))

		runBash(fmt.Sprintf("cd %s && ./easyrsa gen-crl 1>/dev/null", *easyrsaDirPath))
		oAdmin.clients = oAdmin.usersList()
		chmodFix()
		return true, fmt.Sprintf("{\"msg\":\"User %s successfully rotated\"}", username)
	}
	oAdmin.clients = oAdmin.usersList()
	return true, ""
}

func (oAdmin *OvpnAdmin) userDelete(username string) string {
	_, usersFromIndexTxt, err := checkUserExist(username)
	if err != nil {
		return fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}
	if *storageBackend == "kubernetes.secrets" {
		err := app.easyrsaDelete(username)
		if err != nil {
			log.Error(err)
		}
	} else {
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
	}
	chmodFix()
	oAdmin.clients = oAdmin.usersList()
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

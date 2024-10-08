package main

import (
	"errors"
	"fmt"
	"log"
	"rpiadm/backend/openvpn"
	"time"
)

// WARN: highly risky
func (app *OvpnAdmin) userChangePassword(username, password string) error {
	device := app.getDevice(username)
	if device != nil {
		return errors.New(fmt.Sprintf("User '%s' does not exist", username))
	}
	return openvpn.UserChangePassword(*authDatabase, username, password)
}

func (app *OvpnAdmin) userRevoke(username string) error {
	//log.Printf("Revoke certificate for user %s", username)
	client := app.getDevice(username)
	if client == nil {
		return errors.New(fmt.Sprintf("User \"%s\" not found", username))
	}

	err := openvpn.RevokeCertificate(app.easyrsa, *authByPassword, *authDatabase, client.Certificate)
	if err != nil {
		return errors.New(fmt.Sprintf("Fail to revoke certificat for \"%s\": ", err.Error()))
	}

	client.Certificate.Flag = "R"
	client.Certificate.RevocationDate = time.Now().Format(time.RFC3339)
	app.createOrUpdateDeviceByCertificate(client.Certificate)
	app.updateCertificateStats()

	if client != nil {
		if len(client.Connections) > 0 {
			log.Printf("User %s connected: %d", username, len(client.Connections))
			app.mgmt.KillUserConnections(client)
		} else {
			log.Printf("User %s not connected", username)
		}
	}

	return nil
}

func (app *OvpnAdmin) userUnrevoke(username string) error {
	client := app.getDevice(username)

	if client == nil {
		return errors.New(fmt.Sprintf("User \"%s\" not found", username))
	}

	err := openvpn.UserUnrevoke(app.easyrsa, *authByPassword, *authDatabase, client.Certificate)
	if err != nil {
		return errors.New(fmt.Sprintf("Fail to unrevoke certificat for \"%s\": ", err.Error()))
	}

	client.Certificate.Flag = "V"
	client.Certificate.RevocationDate = ""
	app.createOrUpdateDeviceByCertificate(client.Certificate)
	app.updateCertificateStats()
	return nil
}

func (app *OvpnAdmin) userRotate(username string, newDefinition *openvpn.UserDefinition) error {
	device := app.getDevice(username)
	if device == nil {
		return errors.New(fmt.Sprintf("User \"%s\" not found\"", username))
	}
	openvpn.UserRotate(
		app.easyrsa,
		*authByPassword,
		*authDatabase,
		username,
		newDefinition,
	)

	app.updateCertificateStats()
	return nil
}

func (app *OvpnAdmin) userDelete(username string) error {
	client := app.getDevice(username)
	if client == nil {
		return errors.New(fmt.Sprintf("User \"%s\" not found\"", username))
	}

	if err := openvpn.UserDelete(app.easyrsa, client.Certificate); err != nil {
		return err
	}

	app.updateCertificateStats()
	return nil
}

package main

import (
	"errors"
	"fmt"
	"log"
	"rpiadm/backend/openvpn"
	"strings"
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

func (app *OvpnAdmin) userRevoke(commonNameSerialNumber string) error {
	//log.Printf("Revoke certificate for user %s", commonNameSerialNumber)
	parts := strings.Split(commonNameSerialNumber, ":")
	if len(parts) != 2 {
		return errors.New("bad certificate identifier")
	}

	cert, _ := app.easyrsa.FindCertificateBySerial(parts[0], parts[1])

	if cert == nil {
		return errors.New(fmt.Sprintf("Certificate %s with serial %s not found", parts[0], parts[1]))
	}
	//if client == nil {
	//	return errors.New(fmt.Sprintf("User \"%s\" not found", commonNameSerialNumber))
	//}

	if cert.Flag != "V" {
		return errors.New(fmt.Sprintf("Certificate %s is not valid state (is %s)", cert.Username, cert.Flag))
	}

	// patch file in case of filesystem error
	openvpn.RestoreCertBySerial(app.easyrsa, cert.SerialNumber, cert.Username)

	err := app.easyrsa.RevokeCertificate(cert.Username, openvpn.HexToBigInt(cert.SerialNumber))
	//client.Certificate.Flag = "R"
	if err != nil {
		return errors.New(fmt.Sprintf("Fail to revoke certificat for \"%s\": ", err.Error()))
	}

	log.Printf("certificate revoked, update memory")
	client := app.getDevice(parts[0])
	if client == nil {
		return nil
	}

	cert, _ = app.easyrsa.FindUnrevokedCertificate(parts[0])
	if cert == nil {
		client.Certificate.Flag = "R"
		client.Certificate.RevocationDate = time.Now().Format(time.RFC3339)
	} else {
		client.Certificate = cert
	}
	app.createOrUpdateDeviceByCertificate(client.Certificate)
	app.updateCertificateStats()

	if client.Certificate.Flag == "R" {
		if len(client.Connections) > 0 {
			log.Printf("User %s connected: %d", commonNameSerialNumber, len(client.Connections))
			app.mgmt.KillUserConnections(client)
		} else {
			log.Printf("User %s not connected", commonNameSerialNumber)
		}
	}

	return nil
}

func (app *OvpnAdmin) userUnrevoke(commonNameSerialNumber string) error {
	log.Printf("unrevoke %v", commonNameSerialNumber)
	parts := strings.Split(commonNameSerialNumber, ":")
	if len(parts) != 2 {
		return errors.New("bad certificate identifier")
	}

	cert, err := app.easyrsa.UnrevokeCertificate(*authByPassword, *authDatabase, parts[0], parts[1])
	if err != nil {
		return errors.New(fmt.Sprintf("Fail to unrevoke certificat for \"%s\": ", err.Error()))
	}

	client := app.getDevice(cert.Username)

	if client == nil {
		return errors.New(fmt.Sprintf("User \"%s\" not found", parts[0]))
	}
	client.Certificate = cert
	//client.Certificate.Flag = "V"
	//client.Certificate.RevocationDate = ""
	app.createOrUpdateDeviceByCertificate(client.Certificate)
	app.updateCertificateStats()
	return nil
}

func (app *OvpnAdmin) userRotate(commonName string, newDefinition *openvpn.UserDefinition) (*openvpn.Certificate, error) {

	if commonName == app.serverConf.MasterCn {
		cert, err := app.easyrsa.RotateServerCert(newDefinition, app.serverConf.ServerCert)
		return cert, err
	}

	cert, err := app.easyrsa.RotateClientCert(commonName, newDefinition)
	if err != nil {
		return nil, err
	}

	app.createOrUpdateDeviceByCertificate(cert)
	app.easyrsa.RebuildClientRevocationList()
	app.updateCertificateStats()
	return cert, nil
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

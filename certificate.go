package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

type Route struct {
	Address       string `json:"address"`
	Netmask       string `json:"netmask"`
	Description   string `json:"description"`
}

type Ccd struct {
	User          string     `json:"user"`
	ClientAddress string     `json:"clientAddress"`
	CustomRoutes  []Route    `json:"customRoutes"`
	CustomIRoutes []Route    `json:"customIRoutes"`
}

type Certificate struct {
	Identity          string              `json:"identity"`
	Country           string              `json:"country"`
	Province          string              `json:"province"`
	City              string              `json:"city"`
	Organisation      string              `json:"organisation"`
	OrganisationUnit  string              `json:"organisationUnit"`
	Email             string              `json:"email"`
	ExpirationDate    string              `json:"expirationDate"`
	RevocationDate    string              `json:"revocationDate"`
	DeletionDate      string              `json:"deletionDate"`
	flag              string
	SerialNumber      string              `json:"serialNumber"`
	Filename          string              `json:"filename"`
	AccountStatus     string              `json:"accountStatus"`
}

type ClientCertificate struct {
	Certificate       *Certificate        `json:"certificate"`
	Username          string              `json:"username"`

	ConnectionStatus  string              `json:"connectionStatus"`
	Connections       []*VpnClientConnection `json:"connections"`
	Rpic              []*WsRpiConnection  `json:"rpic"`
	RpiState          *RpiState           `json:"rpiState,omitempty"`
}

type RevokedCert struct {
	RevokedTime time.Time         `json:"revokedTime"`
	CommonName  string            `json:"commonName"`
	Cert        *x509.Certificate `json:"cert"`
}

func (app *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

func (app *OvpnAdmin) getCommonNameFromCertificate(path string) *x509.Certificate {
	caCert, err := os.ReadFile(path)
	if err != nil {
		log.Printf("error read file %s: %s", app.serverConf.ca, err.Error())
		return nil
	}

	certPem, _ := pem.Decode(caCert)
	certPemBytes := certPem.Bytes

	cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Printf("error parse certificate ca.crt: %s\n", err.Error())
		return nil
	}

	return cert
}

// decode certificate from PEM to x509
func decodeCert(certPEMBytes []byte) (cert *x509.Certificate, err error) {
	certPem, _ := pem.Decode(certPEMBytes)
	certPemBytes := certPem.Bytes

	cert, err = x509.ParseCertificate(certPemBytes)
	if err != nil {
		return
	}

	return
}

// decode private key from PEM to RSA format
func decodePrivKey(privKey []byte) (key *rsa.PrivateKey, err error) {
	privKeyPem, _ := pem.Decode(privKey)
	key, err = x509.ParsePKCS1PrivateKey(privKeyPem.Bytes)
	if err == nil {
		return
	}

	tmp, err := x509.ParsePKCS8PrivateKey(privKeyPem.Bytes)
	if err != nil {
		err = errors.New("error parse private key")
		return
	}
	key, _ = tmp.(*rsa.PrivateKey)

	return
}

// return PEM encoded private key
func genPrivKey() (privKeyPEM *bytes.Buffer, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)

	//privKeyPKCS1 := x509.MarshalPKCS1PrivateKey(privKey)

	privKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return
	}

	privKeyPEM = new(bytes.Buffer)
	err = pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyPKCS8,
	})


	return
}

// return PEM encoded certificate
func genCA(privKey *rsa.PrivateKey) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	issuerSerial, err := rand.Int(rand.Reader, serialNumberRange)

	issuerTemplate := x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		SerialNumber:          issuerSerial,
		Subject: pkix.Name{
			CommonName: "ca",
		},

		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded certificate
func genServerCert(privKey, caPrivKey *rsa.PrivateKey, ca *x509.Certificate, cn string) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberRange)

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   time.Now(),
		NotAfter:    ca.NotAfter,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded certificate
func genClientCert(privKey, caPrivKey *rsa.PrivateKey, ca *x509.Certificate, cn string) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberRange)

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:   time.Now(),
		NotAfter:    ca.NotAfter,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded CRL
func genCRL(certs []*RevokedCert, ca *x509.Certificate, caKey *rsa.PrivateKey) (crlPEM *bytes.Buffer, err error) {
	var revokedCertificates []pkix.RevokedCertificate

	for _, cert := range certs {
		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{SerialNumber: cert.Cert.SerialNumber, RevocationTime: cert.RevokedTime})
	}

	revocationList := &x509.RevocationList{
		//SignatureAlgorithm: x509.SHA256WithRSA,
		RevokedCertificates: revokedCertificates,
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(180 * time.Hour * 24),
		//ExtraExtensions: []pkix.Extension{},
	}

	crl, err := x509.CreateRevocationList(rand.Reader, revocationList, ca, caKey)
	if err != nil {
		return nil, err
	}

	crlPEM = new(bytes.Buffer)
	err = pem.Encode(crlPEM, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	})
	if err != nil {
		return
	}

	return
}

func (app *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		err := fDelete(certsArchivePath)
		if err != nil {
			log.Printf("failed to delete cert archive %v", err)
		}
	}

	err := fDownload(certsArchivePath, *masterHost+downloadCertsApiUrl+"?token="+app.masterSyncToken, app.masterHostBasicAuth)
	if err != nil {
		log.Printf("failed to download files %v", err)
		return false
	}

	return true
}

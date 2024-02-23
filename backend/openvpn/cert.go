package openvpn

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"gopkg.in/alessio/shellescape.v1"
	"log"
	"math/big"
	"os"
	"regexp"
	"rpiadm/backend/shell"
	"strings"
	"time"
)

const (
	indexTxtDateLayout = "060102150405Z"
	stringDateFormat   = "2006-01-02 15:04:05"
	usernameRegexp     = `^([a-zA-Z0-9_.\-@])+$`
	passwordMinLength  = 6
)

type RevokedCert struct {
	RevokedTime time.Time         `json:"revokedTime"`
	CommonName  string            `json:"commonName"`
	Cert        *x509.Certificate `json:"cert"`
}

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

type Route struct {
	Address     string `json:"address"`
	Netmask     string `json:"netmask"`
	Description string `json:"description"`
}

type Ccd struct {
	User          string  `json:"user"`
	ClientAddress string  `json:"clientAddress"`
	CustomRoutes  []Route `json:"customRoutes"`
	CustomIRoutes []Route `json:"customIRoutes"`
}

type Certificate struct {
	Identity         string `json:"identity"`
	Username         string `json:"username"`
	Country          string `json:"country"`
	Province         string `json:"province"`
	City             string `json:"city"`
	Organisation     string `json:"organisation"`
	OrganisationUnit string `json:"organisationUnit"`
	Email            string `json:"email"`
	ExpirationDate   string `json:"expirationDate"`
	RevocationDate   string `json:"revocationDate"`
	DeletionDate     string `json:"deletionDate"`
	Flag             string
	SerialNumber     string `json:"serialNumber"`
	Filename         string `json:"filename"`
	AccountStatus    string `json:"accountStatus"`
}

func parseDate(layout, datetime string) time.Time {
	t, err := time.Parse(layout, datetime)
	if err != nil {
		log.Printf("error parsing date %s: %v", datetime, err.Error())
	}
	return t
}

func parseDateToString(layout, datetime, format string) string {
	return parseDate(layout, datetime).Format(format)
}

func parseDateToUnix(layout, datetime string) int64 {
	return parseDate(layout, datetime).Unix()
}

func CreateClientCertificate(identity string, flag string, expirationDate string, revocationDate *string, serialNumber string, filename string) *Certificate {
	apochNow := time.Now().Unix()
	cert := new(Certificate)
	cert.Username = extractUsername(identity)
	cert.Flag = flag
	cert.ExpirationDate = parseDateToString(indexTxtDateLayout, expirationDate, stringDateFormat)
	if revocationDate != nil && *revocationDate != "" {
		cert.RevocationDate = parseDateToString(indexTxtDateLayout, *revocationDate, stringDateFormat)
	}
	cert.SerialNumber = serialNumber
	cert.Filename = filename
	cert.Identity = identity
	cert.AccountStatus = "Active"

	cert.Country = extractCountry(cert.Identity)
	cert.Province = extractProvince(cert.Identity)
	cert.City = extractCity(cert.Identity)
	cert.Organisation = extractOrganisation(cert.Identity)
	cert.OrganisationUnit = extractOrganisationUnit(cert.Identity)
	cert.Email = extractEmail(cert.Identity)
	if (parseDateToUnix(stringDateFormat, cert.ExpirationDate) - apochNow) < 0 {
		cert.AccountStatus = "Expired"
	}
	cert.DeletionDate = extractDeletionDate(identity)
	if len(cert.DeletionDate) > 0 {

		//log.Printf("mark '%s' as DELETED at: %s\n", line.Username, line.DeletionDate)
		cert.Flag = "D"
	}
	return cert
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

func validateUsername(username string) bool {
	var validUsername = regexp.MustCompile(usernameRegexp)
	return validUsername.MatchString(username)
}

func checkUserActiveExist(indexTxtPath string, username string) bool {
	for _, u := range IndexTxtParserCertificate(shell.ReadFile(indexTxtPath)) {
		if u.Username == username && u.Flag == "V" {
			return true
		}
	}
	return false
}

func ValidatePassword(password string) error {
	if len(password) < passwordMinLength {
		return errors.New(fmt.Sprintf("Password for too short, password length must be greater or equal %d", passwordMinLength))
	} else {
		return nil
	}
}

func UserCreateCertificate(easyrsaDirPath string, easyrsaBinPath string, authByPassword bool, authDatabase string, definition UserDefinition) (*Certificate, error) {

	if !validateUsername(definition.Username) {
		return nil, errors.New(fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", definition.Username, usernameRegexp))
	}

	if checkUserActiveExist(easyrsaDirPath+"/pki/index.txt", definition.Username) {
		return nil, errors.New(fmt.Sprintf("User \"%s\" already exists", definition.Username))
	}

	if authByPassword && ValidatePassword(definition.Password) == nil {
		return nil, errors.New(fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength))
	}

	cmd := fmt.Sprintf(
		"cd %s && "+
			"EASYRSA_REQ_COUNTRY=%s "+
			"EASYRSA_REQ_PROVINCE=%s "+
			"EASYRSA_REQ_CITY=%s "+
			"EASYRSA_REQ_ORG=%s "+
			"EASYRSA_REQ_OU=%s "+
			"EASYRSA_REQ_EMAIL=%s "+
			"%s "+
			"--dn-mode=org "+
			"--batch "+
			"build-client-full %s nopass 1>/dev/null",
		shellescape.Quote(easyrsaDirPath),
		shellescape.Quote(definition.Country),
		shellescape.Quote(definition.Province),
		shellescape.Quote(definition.City),
		shellescape.Quote(definition.Organisation),
		shellescape.Quote(definition.OrganisationUnit),
		shellescape.Quote(definition.Email),
		shellescape.Quote(easyrsaBinPath),
		shellescape.Quote(definition.Username),
	)

	o, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("Error creating certificate \"%s\", using \"cmd\" %s", err, cmd)
		return nil, errors.New(fmt.Sprintf("Error creating certificate \"%s\"", err))
	}

	log.Printf("cert generated %s", o)

	if authByPassword {
		o, err := shell.RunBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", authDatabase, definition.Username, definition.Password))
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error creating user in DB \"%s\"", err))
		}
		log.Printf("create password for %s: %s", definition.Username, o)
	}

	log.Printf("Certificate for user %s issued", definition.Username)

	return &Certificate{
		//Identity         string `json:"identity"`
		Username:         definition.Username,
		Country:          definition.Country,
		Province:         definition.Province,
		City:             definition.City,
		Organisation:     definition.Organisation,
		OrganisationUnit: definition.OrganisationUnit,
		Email:            definition.Email,
		//ExpirationDate   string `json:"expirationDate"`
		//RevocationDate   string `json:"revocationDate"`
		//DeletionDate     string `json:"deletionDate"`
		Flag: "V",
		//SerialNumber     string `json:"serialNumber"`
		//Filename         string `json:"filename"`
		//AccountStatus    string `json:"accountStatus"`
	}, nil
}

func IndexTxtParserCertificate(txt string) []*Certificate {
	var indexTxt = make([]*Certificate, 0)

	txtLinesArray := strings.Split(txt, "\n")
	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) <= 0 {
			continue
		}
		switch {
		case strings.HasPrefix(str[0], "V"):
			identity := strings.Join(str[4:], " ")
			indexTxt = append(indexTxt, CreateClientCertificate(identity, "V", str[1], nil, str[2], str[3]))
		case strings.HasPrefix(str[0], "R"):
			identity := strings.Join(str[5:], " ")
			indexTxt = append(indexTxt, CreateClientCertificate(identity, "R", str[1], &str[2], str[3], str[4]))
		}
	}

	return indexTxt
}

func GetCommonNameFromCertificate(path string) *x509.Certificate {
	caCert, err := os.ReadFile(path)
	if err != nil {
		log.Printf("error read file %s: %s", path, err.Error())
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

func RebuildClientRevocationList(easyrsaBinPath string, easyrsaDirPath string) {
	log.Printf("rebuild CRL")
	_, err := shell.RunBash(fmt.Sprintf("cd %s && %s gen-crl", easyrsaDirPath, easyrsaBinPath))
	if err != nil {
		log.Printf("fail to rebuild crl", err)
	}
	chmodFix(easyrsaDirPath)
}

func RestoreCertBySerial(easyrsaDirPath string, serial string, cn string) error {

	copyCertFile(
		easyrsaDirPath,
		fmt.Sprintf("/pki/revoked/certs_by_serial/%s.crt", serial),
		fmt.Sprintf("/pki/issued/%s.crt", cn),
	)

	copyCertFile(
		easyrsaDirPath,
		fmt.Sprintf("/pki/revoked/certs_by_serial/%s.crt", serial),
		fmt.Sprintf("/pki/certs_by_serial/%s.pem", serial),
	)

	copyCertFile(
		easyrsaDirPath,
		fmt.Sprintf("/pki/revoked/private_by_serial/%s.key", serial),
		fmt.Sprintf("/pki/private/%s.key", cn),
	)

	copyCertFile(
		easyrsaDirPath,
		fmt.Sprintf("/pki/revoked/reqs_by_serial/%s.req", serial),
		fmt.Sprintf("/pki/reqs/%s.req", cn),
	)

	if fExistsPki(easyrsaDirPath, fmt.Sprintf("/pki/issued/%s.crt", cn)) && fExistsPki(easyrsaDirPath, fmt.Sprintf("/pki/certs_by_serial/%s.pem", serial)) {
		os.Remove(easyrsaDirPath + fmt.Sprintf("/pki/revoked/certs_by_serial/%s.crt", serial))
	}
	if fExistsPki(easyrsaDirPath, fmt.Sprintf("/pki/private/%s.key", cn)) {
		os.Remove(easyrsaDirPath + fmt.Sprintf("/pki/revoked/private_by_serial/%s.key", serial))
	}
	if fExistsPki(easyrsaDirPath, fmt.Sprintf("/pki/reqs/%s.req", cn)) {
		os.Remove(easyrsaDirPath + fmt.Sprintf("/pki/revoked/reqs_by_serial/%s.req", serial))
	}
	return nil
}

func fExistsPki(path string, f string) bool {
	return shell.FileExist(path)
}

func copyCertFile(base string, from string, to string) error {
	if !shell.FileExist(base + from) {
		log.Printf("source file %s does not exists", base+from)
		return nil
	}
	if shell.FileExist(base + to) {
		log.Printf("target file %s already exists", base+to)
		return nil
	}

	err := shell.FileCopy(base+from, base+to)
	if err == nil {
		log.Printf("Moved %s to %s", from, to)
	}
	return err
}

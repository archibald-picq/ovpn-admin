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
	crlDateFormat      = "Jan 02 15:04:05 2006 MST"
	usernameRegexp     = `^([a-zA-Z0-9_.\-@])+$`
	passwordMinLength  = 6
)

type RevokedCert struct {
	RevokedTime  time.Time    `json:"revokedTime"`
	SerialNumber string       `json:"serialNumber"`
	CommonName   *string      `json:"commonName,omitempty"`
	Cert         *Certificate `json:"cert,omitempty"`
}

type BaseCertificate struct {
	CommonName       string `json:"commonName"`
	Email            string `json:"email"`
	Country          string `json:"country"`
	Province         string `json:"province"`
	City             string `json:"city"`
	Organisation     string `json:"organisation"`
	OrganisationUnit string `json:"organisationUnit"`
}

type UserDefinition struct {
	//Account
	CommonName       string `json:"commonName"`
	Password         string `json:"password"`
	Email            string `json:"email"`
	Country          string `json:"country"`
	Province         string `json:"province"`
	City             string `json:"city"`
	Organisation     string `json:"organisation"`
	OrganisationUnit string `json:"organisationUnit"`
	Ccd              *Ccd   `json:"ccd"`
}

type Route struct {
	Address     string `json:"address"`
	Netmask     string `json:"netmask"`
	Description string `json:"description"`
}

type Ccd struct {
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

func BuildClientCertificate(identity string, flag string, expirationDate string, revocationDate *string, serialNumber string, filename string) *Certificate {
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

		//log.Printf("mark '%s' as DELETED at: %s\n", line.CommonName, line.DeletionDate)
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

func checkUserActiveExist(easyrsa Easyrsa, username string) bool {
	for _, u := range IndexTxtParserCertificate(easyrsa) {
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

func CreateCaCertificate(easyrsa Easyrsa, authByPassword bool, authDatabase string, definition UserDefinition) (*Certificate, error) {
	log.Printf("CreateCaCertificate(%s)", definition.CommonName)
	if !shell.FileExist(easyrsa.EasyrsaDirPath + "/pki") {
		err := shell.CreateDir(easyrsa.EasyrsaDirPath + "/pki")
		if err != nil {
			return nil, errors.New("cant create pki dir")
		}
	}

	if !validateUsername(definition.CommonName) {
		return nil, errors.New(fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", definition.CommonName, usernameRegexp))
	}

	if checkUserActiveExist(easyrsa, definition.CommonName) {
		return nil, errors.New(fmt.Sprintf("User \"%s\" already exists", definition.CommonName))
	}

	if authByPassword && ValidatePassword(definition.Password) == nil {
		return nil, errors.New(fmt.Sprintf("Key too short, password length must be greater or equal %d", passwordMinLength))
	}

	cmd := fmt.Sprintf(
		"cd %s && "+
			"EASYRSA_REQ_CN=%s "+
			"EASYRSA_REQ_COUNTRY=%s "+
			"EASYRSA_REQ_PROVINCE=%s "+
			"EASYRSA_REQ_CITY=%s "+
			"EASYRSA_REQ_ORG=%s "+
			"EASYRSA_REQ_OU=%s "+
			"EASYRSA_REQ_EMAIL=%s "+
			"%s --dn-mode=org --batch build-ca %s nopass 1>/dev/null",
		shellescape.Quote(easyrsa.EasyrsaDirPath),
		shellescape.Quote(definition.CommonName),
		shellescape.Quote(definition.Country),
		shellescape.Quote(definition.Province),
		shellescape.Quote(definition.City),
		shellescape.Quote(definition.Organisation),
		shellescape.Quote(definition.OrganisationUnit),
		shellescape.Quote(definition.Email),
		shellescape.Quote(easyrsa.EasyrsaBinPath),
		shellescape.Quote(definition.CommonName),
	)

	log.Printf("cmd %s", cmd)
	o, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("Error creating certificate \"%s\", using \"cmd\" %s", err, cmd)
		return nil, errors.New(fmt.Sprintf("Error creating certificate \"%s\"", err))
	}

	log.Printf("cert generated %s", o)

	//if authByPassword {
	//	o, err := shell.RunBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", authDatabase, definition.CommonName, definition.Password))
	//	if err != nil {
	//		return nil, errors.New(fmt.Sprintf("Error creating user in DB \"%s\"", err))
	//	}
	//	log.Printf("create password for %s: %s", definition.CommonName, o)
	//}

	log.Printf("Certificate for user %s issued", definition.CommonName)

	//for _, cert := range IndexTxtParserCertificate(easyrsa) {
	//	if cert.Username == definition.CommonName {
	//		return cert, nil
	//	}
	//}

	return nil, nil
	//errors.New("cant find just created certificate")
}

func DhPemExists(easyrsa Easyrsa) bool {
	return shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/dh.pem")
}

func CreateDhFile(easyrsa Easyrsa) error {
	if shell.FileExist(easyrsa.EasyrsaDirPath + "/pki/dh.pem") {
		return nil
	}
	cmd := fmt.Sprintf(
		"cd %s && %s gen-dh 1>/dev/null",
		shellescape.Quote(easyrsa.EasyrsaDirPath),
		shellescape.Quote(easyrsa.EasyrsaBinPath),
	)

	log.Printf("cmd %s", cmd)
	o, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("Error generating DH file \"%s\", using \"cmd\" %s", err, cmd)
		return errors.New(fmt.Sprintf("Error generating DH file \"%s\"", err))
	}

	log.Printf("cert generated %s", o)
	return nil
}

func CreateServerCertificate(easyrsa Easyrsa, authByPassword bool, authDatabase string, definition UserDefinition) (*Certificate, error) {
	log.Printf("CreateServerCertificate(%s)", definition.CommonName)

	if !validateUsername(definition.CommonName) {
		return nil, errors.New(fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", definition.CommonName, usernameRegexp))
	}

	if checkUserActiveExist(easyrsa, definition.CommonName) {
		return nil, errors.New(fmt.Sprintf("User \"%s\" already exists", definition.CommonName))
	}

	if authByPassword && ValidatePassword(definition.Password) == nil {
		return nil, errors.New(fmt.Sprintf("Key too short, password length must be greater or equal %d", passwordMinLength))
	}

	cmd := fmt.Sprintf(
		"cd %s && "+
			"EASYRSA_REQ_COUNTRY=%s "+
			"EASYRSA_REQ_PROVINCE=%s "+
			"EASYRSA_REQ_CITY=%s "+
			"EASYRSA_REQ_ORG=%s "+
			"EASYRSA_REQ_OU=%s "+
			"EASYRSA_REQ_EMAIL=%s "+
			"%s --dn-mode=org --batch build-server-full %s nopass 1>/dev/null",
		shellescape.Quote(easyrsa.EasyrsaDirPath),
		shellescape.Quote(definition.Country),
		shellescape.Quote(definition.Province),
		shellescape.Quote(definition.City),
		shellescape.Quote(definition.Organisation),
		shellescape.Quote(definition.OrganisationUnit),
		shellescape.Quote(definition.Email),
		shellescape.Quote(easyrsa.EasyrsaBinPath),
		shellescape.Quote(definition.CommonName),
	)

	log.Printf("cmd %s", cmd)
	o, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("Error creating certificate \"%s\", using \"cmd\" %s", err, cmd)
		return nil, errors.New(fmt.Sprintf("Error creating certificate \"%s\"", err))
	}

	log.Printf("cert generated %s", o)

	//if authByPassword {
	//	o, err := shell.RunBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", authDatabase, definition.CommonName, definition.Password))
	//	if err != nil {
	//		return nil, errors.New(fmt.Sprintf("Error creating user in DB \"%s\"", err))
	//	}
	//	log.Printf("create password for %s: %s", definition.CommonName, o)
	//}

	log.Printf("Certificate for user %s issued", definition.CommonName)

	for _, cert := range IndexTxtParserCertificate(easyrsa) {
		if cert.Username == definition.CommonName {
			return cert, nil
		}
	}

	return nil, errors.New("cant find just created certificate")
}

func CreateClientCertificate(easyrsa Easyrsa, authByPassword bool, authDatabase string, definition UserDefinition) (*Certificate, error) {
	log.Printf("CreateClientCertificate(%s)", definition.CommonName)

	if !validateUsername(definition.CommonName) {
		return nil, errors.New(fmt.Sprintf("Username \"%s\" incorrect, you can use only %s\n", definition.CommonName, usernameRegexp))
	}

	if checkUserActiveExist(easyrsa, definition.CommonName) {
		return nil, errors.New(fmt.Sprintf("User \"%s\" already exists", definition.CommonName))
	}

	if authByPassword && ValidatePassword(definition.Password) == nil {
		return nil, errors.New(fmt.Sprintf("Key too short, password length must be greater or equal %d", passwordMinLength))
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
		shellescape.Quote(easyrsa.EasyrsaDirPath),
		shellescape.Quote(definition.Country),
		shellescape.Quote(definition.Province),
		shellescape.Quote(definition.City),
		shellescape.Quote(definition.Organisation),
		shellescape.Quote(definition.OrganisationUnit),
		shellescape.Quote(definition.Email),
		shellescape.Quote(easyrsa.EasyrsaBinPath),
		shellescape.Quote(definition.CommonName),
	)

	log.Printf("cmd %s", cmd)
	o, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("Error creating certificate \"%s\", using \"cmd\" %s", err, cmd)
		return nil, errors.New(fmt.Sprintf("Error creating certificate \"%s\"", err))
	}

	log.Printf("cert generated %s", o)

	if authByPassword {
		o, err := shell.RunBash(fmt.Sprintf("openvpn-user create --db.path %s --user %s --password %s", authDatabase, definition.CommonName, definition.Password))
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error creating user in DB \"%s\"", err))
		}
		log.Printf("create password for %s: %s", definition.CommonName, o)
	}

	log.Printf("Certificate for user %s issued", definition.CommonName)

	for _, cert := range IndexTxtParserCertificate(easyrsa) {
		if cert.Username == definition.CommonName {
			return cert, nil
		}
	}

	return nil, errors.New("cant find just created certificate")
	//return &Certificate{
	//	//Identity         string `json:"identity"`
	//	CommonName:         definition.CommonName,
	//	Country:          definition.Country,
	//	Province:         definition.Province,
	//	City:             definition.City,
	//	Organisation:     definition.Organisation,
	//	OrganisationUnit: definition.OrganisationUnit,
	//	Email:            definition.Email,
	//	//ExpirationDate   string `json:"expirationDate"`
	//	//RevocationDate   string `json:"revocationDate"`
	//	//DeletionDate     string `json:"deletionDate"`
	//	Flag: "V",
	//	//SerialNumber     string `json:"serialNumber"`
	//	//Filename         string `json:"filename"`
	//	//AccountStatus    string `json:"accountStatus"`
	//}, nil
}
func ReadCertificateX509(path string) (*x509.Certificate, error) {
	caCert, err := os.ReadFile(path)
	if err != nil {
		//log.Printf("error read file %s: %s", path, err.Error())
		return nil, err
	}

	certPem, _ := pem.Decode(caCert)
	certPemBytes := certPem.Bytes

	x509cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Printf("error parse certificate '%s': %s", path, err.Error())
		return nil, err
	}
	return x509cert, nil
}

func IsValidServerCert(easyrsa Easyrsa, commonName string) bool {
	path := easyrsa.EasyrsaDirPath + "/pki/issued/" + commonName + ".crt"
	if !shell.FileExist(path) {
		return false
	}
	x509cert, err := ReadCertificateX509(path)
	if err != nil {
		log.Printf("can't read cert '%s': %v", path, err)
		return false
	}
	return isServerCert(x509cert)
}

func ReadCertificate(path string) *BaseCertificate {
	x509cert, err := ReadCertificateX509(path)
	if err != nil {
		log.Printf("error reading certificate '%s': %s", path, err.Error())
		return nil
	}
	return MapX509ToCertificate(x509cert)
}

func MapX509ToCertificate(x509cert *x509.Certificate) *BaseCertificate {

	var cert BaseCertificate
	cert.CommonName = x509cert.Subject.CommonName
	if len(x509cert.EmailAddresses) > 0 {
		cert.Email = x509cert.EmailAddresses[0]
	}
	if len(x509cert.Subject.Country) > 0 {
		cert.Country = x509cert.Subject.Country[0]
	}
	if len(x509cert.Subject.Province) > 0 {
		cert.Province = x509cert.Subject.Province[0]
	}
	if len(x509cert.Subject.Locality) > 0 {
		cert.City = x509cert.Subject.Locality[0]
	}
	if len(x509cert.Subject.Organization) > 0 {
		cert.Organisation = x509cert.Subject.Organization[0]
	}
	if len(x509cert.Subject.OrganizationalUnit) > 0 {
		cert.OrganisationUnit = x509cert.Subject.OrganizationalUnit[0]
	}
	return &cert
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

// decode private Key from PEM to RSA format
func decodePrivKey(privKey []byte) (key *rsa.PrivateKey, err error) {
	privKeyPem, _ := pem.Decode(privKey)
	key, err = x509.ParsePKCS1PrivateKey(privKeyPem.Bytes)
	if err == nil {
		return
	}

	tmp, err := x509.ParsePKCS8PrivateKey(privKeyPem.Bytes)
	if err != nil {
		err = errors.New("error parse private Key")
		return
	}
	key, _ = tmp.(*rsa.PrivateKey)

	return
}

// return PEM encoded private Key
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
//func genCRL(certs []*RevokedCert, ca *x509.Certificate, caKey *rsa.PrivateKey) (crlPEM *bytes.Buffer, err error) {
//	var revokedCertificates []pkix.RevokedCertificate
//
//	for _, cert := range certs {
//		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{
//			SerialNumber:   cert.Cert.SerialNumber,
//			RevocationTime: cert.RevokedTime,
//		})
//	}
//
//	revocationList := &x509.RevocationList{
//		//SignatureAlgorithm: x509.SHA256WithRSA,
//		RevokedCertificates: revokedCertificates,
//		Number:              big.NewInt(1),
//		ThisUpdate:          time.Now(),
//		NextUpdate:          time.Now().Add(180 * time.Hour * 24),
//		//ExtraExtensions: []pkix.Extension{},
//	}
//
//	crl, err := x509.CreateRevocationList(rand.Reader, revocationList, ca, caKey)
//	if err != nil {
//		return nil, err
//	}
//
//	crlPEM = new(bytes.Buffer)
//	err = pem.Encode(crlPEM, &pem.Block{
//		Type:  "X509 CRL",
//		Bytes: crl,
//	})
//	if err != nil {
//		return
//	}
//
//	return
//}

func RebuildClientRevocationList(easyrsa Easyrsa) {
	log.Printf("rebuild CRL")
	_, err := shell.RunBash(fmt.Sprintf("cd %s && %s gen-crl", easyrsa.EasyrsaDirPath, easyrsa.EasyrsaBinPath))
	if err != nil {
		log.Printf("fail to rebuild crl", err)
	}
	chmodFix(easyrsa.EasyrsaDirPath)
}

var (
	regSerialNumber   = regexp.MustCompile(`^\s*Serial Number:\s*(.*)$`)
	regRevocationDate = regexp.MustCompile(`^\s*Revocation Date:\s*(.*)$`)
)

func GetCrlList(crlFile string, certs []*Certificate) ([]*RevokedCert, error) {
	out, err := shell.RunBash(fmt.Sprintf("openssl crl -text -noout -in %s", crlFile))
	crls := make([]*RevokedCert, 0)
	if err != nil {
		return crls, err
	}
	//log.Printf("stdout: %s", out)
	//log.Printf("stderr: %s", err)

	lines := strings.Split(out, "\n")
	var currentEntry *RevokedCert

	for _, line := range lines {
		line = strings.Trim(line, " ")
		log.Printf("parse '%s'", line)
		if matches := regSerialNumber.FindStringSubmatch(line); len(matches) > 0 {
			if currentEntry != nil {
				crls = append(crls, currentEntry)
				currentEntry = nil
			}
			currentEntry = new(RevokedCert)
			currentEntry.SerialNumber = matches[1]
			log.Printf(" - new entry %s", currentEntry.SerialNumber)
		} else if matches := regRevocationDate.FindStringSubmatch(line); len(matches) > 0 {
			currentEntry.RevokedTime = parseDate(crlDateFormat, matches[1])
			log.Printf("   - new date %v", currentEntry.RevokedTime)
		}
	}

	if currentEntry != nil {
		crls = append(crls, currentEntry)
		currentEntry = nil
	}

	log.Printf("revoked entries: %d", len(crls))

	for _, crl := range crls {
		log.Printf("find cert for serial: %s", crl.SerialNumber)
		for _, cert := range certs {
			if cert.SerialNumber == crl.SerialNumber {
				crl.CommonName = &cert.Username
				crl.Cert = cert
			}
		}
	}

	return crls, nil
}

func RestoreCertBySerial(easyrsa Easyrsa, serial string, cn string) error {
	if len(cn) == 0 {
		return errors.New("certificate name is empty")
	}
	copyCertFile(
		easyrsa.EasyrsaDirPath,
		fmt.Sprintf("/pki/revoked/certs_by_serial/%s.crt", serial),
		fmt.Sprintf("/pki/issued/%s.crt", cn),
	)

	copyCertFile(
		easyrsa.EasyrsaDirPath,
		fmt.Sprintf("/pki/revoked/certs_by_serial/%s.crt", serial),
		fmt.Sprintf("/pki/certs_by_serial/%s.pem", serial),
	)

	copyCertFile(
		easyrsa.EasyrsaDirPath,
		fmt.Sprintf("/pki/revoked/private_by_serial/%s.key", serial),
		fmt.Sprintf("/pki/private/%s.key", cn),
	)

	copyCertFile(
		easyrsa.EasyrsaDirPath,
		fmt.Sprintf("/pki/revoked/reqs_by_serial/%s.req", serial),
		fmt.Sprintf("/pki/reqs/%s.req", cn),
	)

	if fExistsPki(easyrsa.EasyrsaDirPath, fmt.Sprintf("/pki/issued/%s.crt", cn)) && fExistsPki(easyrsa.EasyrsaDirPath, fmt.Sprintf("/pki/certs_by_serial/%s.pem", serial)) {
		os.Remove(easyrsa.EasyrsaDirPath + fmt.Sprintf("/pki/revoked/certs_by_serial/%s.crt", serial))
	}
	if fExistsPki(easyrsa.EasyrsaDirPath, fmt.Sprintf("/pki/private/%s.key", cn)) {
		os.Remove(easyrsa.EasyrsaDirPath + fmt.Sprintf("/pki/revoked/private_by_serial/%s.key", serial))
	}
	if fExistsPki(easyrsa.EasyrsaDirPath, fmt.Sprintf("/pki/reqs/%s.req", cn)) {
		os.Remove(easyrsa.EasyrsaDirPath + fmt.Sprintf("/pki/revoked/reqs_by_serial/%s.req", serial))
	}
	return nil
}

func fExistsPki(path string, f string) bool {
	return shell.FileExist(path + f)
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

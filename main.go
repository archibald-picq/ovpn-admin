package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/dgrijalva/jwt-go"

	"github.com/google/uuid"
	"io/fs"
	"io/ioutil"
	"embed"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	log "github.com/sirupsen/logrus"

	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/alessio/shellescape.v1"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

const (
	usernameRegexp       = `^([a-zA-Z0-9_.-@])+$`
	passwordMinLength    = 6
	downloadCertsApiUrl  = "/api/data/certs/download"
	downloadCcdApiUrl    = "/api/data/ccd/download"
	certsArchiveFileName = "certs.tar.gz"
	ccdArchiveFileName   = "ccd.tar.gz"
	indexTxtDateLayout   = "060102150405Z"
	stringDateFormat     = "2006-01-02 15:04:05"

	kubeNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	serverConfFile           = kingpin.Flag("server.conf", "conf file for the server").Default("/etc/openvpn/server.conf").Envar("OPENVPN_SERVER_CONF").String()
	serverRestartCommand     = kingpin.Flag("restart.cmd", "systemctl restart openvpn@server.service").Default("").Envar("OPENVPN_RESTART_CMD").String()
	listenHost               = kingpin.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort               = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8080").Envar("OVPN_LISTEN_PORT").String()
	serverRole               = kingpin.Flag("role", "server role, master or slave").Default("master").Envar("OVPN_ROLE").HintOptions("master", "slave").String()
	masterHost               = kingpin.Flag("master.host", "URL for the master server").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	masterBasicAuthUser      = kingpin.Flag("master.basic-auth.user", "user for master server's Basic Auth").Default("").Envar("OVPN_MASTER_USER").String()
	masterBasicAuthPassword  = kingpin.Flag("master.basic-auth.password", "password for master server's Basic Auth").Default("").Envar("OVPN_MASTER_PASSWORD").String()
	masterSyncFrequency      = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds").Default("600").Envar("OVPN_MASTER_SYNC_FREQUENCY").Int()
	masterSyncToken          = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	openvpnNetwork           = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("").Envar("OVPN_NETWORK").String()
	openvpnServer            = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("127.0.0.1:7777:tcp").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	openvpnServerBehindLB    = kingpin.Flag("ovpn.server.behindLB", "enable if your OpenVPN server is behind Kubernetes Service having the LoadBalancer type").Default("false").Envar("OVPN_LB").Bool()
	openvpnServiceName       = kingpin.Flag("ovpn.service", "the name of Kubernetes Service having the LoadBalancer type if your OpenVPN server is behind it").Default("openvpn-external").Envar("OVPN_LB_SERVICE").Strings()
	mgmtAddress              = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface; can have multiple values").Default("").Envar("OPENVPN_MANAGEMENT").Strings()
	metricsPath              = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaDirPath           = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("./easyrsa").Envar("EASYRSA_PATH").String()
	indexTxtPath             = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file").Default("").Envar("EASYRSA_INDEX_PATH").String()
	ccdEnabled               = kingpin.Flag("ccd", "enable client-config-dir").Default("false").Envar("OVPN_CCD").Bool()
	ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	ccdTemplatePath          = kingpin.Flag("templates.ccd-path", "path to custom ccd.tpl").Default("").Envar("OVPN_TEMPLATES_CCD_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	logLevel                 = kingpin.Flag("log.level", "set log level: trace, debug, info, warn, error (default info)").Default("info").Envar("LOG_LEVEL").String()
	logFormat                = kingpin.Flag("log.format", "set log format: text, json (default text)").Default("text").Envar("LOG_FORMAT").String()
	storageBackend           = kingpin.Flag("storage.backend", "storage backend: filesystem, kubernetes.secrets (default filesystem)").Default("filesystem").Envar("STORAGE_BACKEND").String()
	jwtSecretFile            = kingpin.Flag("jwt.secret", "jwt secret file").Default("jwt.secret.key").Envar("JWT_SECRET").String()
	adminAccountsFile        = kingpin.Flag("admin.accounts", "Admin accounts files").Default("admin-accounts.json").Envar("ADMIN_ACCOUNT").String()

	certsArchivePath = "/tmp/" + certsArchiveFileName
	ccdArchivePath   = "/tmp/" + ccdArchiveFileName

	version = "2.0.0"
)

var logLevels = map[string]log.Level{
	"trace": log.TraceLevel,
	"debug": log.DebugLevel,
	"info":  log.InfoLevel,
	"warn":  log.WarnLevel,
	"error": log.ErrorLevel,
}

var logFormats = map[string]log.Formatter{
	"text": &log.TextFormatter{},
	"json": &log.JSONFormatter{},
}

var (
	ovpnServerCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_cert_expire",
		Help: "openvpn server certificate expire time in days",
	},
	)

	ovpnServerCaCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_ca_cert_expire",
		Help: "openvpn server CA certificate expire time in days",
	},
	)

	ovpnClientsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_total",
		Help: "total openvpn users",
	},
	)

	ovpnClientsRevoked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_revoked",
		Help: "revoked openvpn users",
	},
	)

	ovpnClientsExpired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_expired",
		Help: "expired openvpn users",
	},
	)

	ovpnClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_connected",
		Help: "total connected openvpn clients",
	},
	)

	ovpnUniqClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_uniq_clients_connected",
		Help: "uniq connected openvpn clients",
	},
	)

	ovpnClientCertificateExpire = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_cert_expire",
		Help: "openvpn user certificate expire time in days",
	},
		[]string{"client"},
	)

	ovpnClientConnectionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_info",
		Help: "openvpn user connection info. ip - assigned address from ovpn network. value - last time when connection was refreshed in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientConnectionFrom = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_from",
		Help: "openvpn user connection info. ip - from which address connection was initialized. value - time when connection was initialized in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientBytesReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_received",
		Help: "openvpn user bytes received",
	},
		[]string{"client"},
	)

	ovpnClientBytesSent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_sent",
		Help: "openvpn user bytes sent",
	},
		[]string{"client"},
	)
)

//go:embed templates/*
var templates embed.FS
//go:embed frontend/static
var content embed.FS

type OvpnConfig struct {
	server                 string   // 10.8.0.0 255.255.255.0
	port                   int      // 1194
	proto                  string   // udp udp6
	dev                    string   // tun tap
	tunMtu                 int      // 60000
	fragment               int      // 0
	user                   string   // nobody
	group                  string   // nogroup
	mssfix                 int      // 0
	management             string   // localhost 7505
	ca                     string   // ca.crt
	cert                   string   // server.crt
	key                    string   // server.key
	dh                     string   // dh2048.pem none
	ifconfigPoolPersist    string   // ipp.txt
	keepalive              string   // 10 120
	compLzo                bool
	persistKey             bool
	persistTun             bool
	status                 string   // /var/log/openvpn/status.log
	verb                   int      // 1 3
	clientConfigDir        string   // ccd
	clientToClient         bool
	duplicateCn            bool
	topology               string   // subnet
	serverIpv6             string   // fd42:42:42:42::/112
	tunIpv6                bool
	ecdhCurve              string   // prime256v1
	tlsCrypt               string   // tls-crypt.key
	crlVerify              string   // crl.pem
	auth                   string   // SHA256
	cipher                 string   // AES-128-GCM
	ncpCiphers             string   // AES-128-GCM
	tlsServer              bool
	tlsVersionMin          string   // 1.2
	tlsCipher              string   // TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
	log                    string   // /var/log/openvpn.log
	route                  []string // 10.42.44.0 255.255.255.0
	                                // 10.42.78.0 255.255.255.0
	                                // 10.8.0.0 255.255.255.0
	push                   []string // "dhcp-option DNS 10.8.0.1"
	                                // "dhcp-option DNS fd42:42:42:42::1"
	                                // "redirect-gateway def1 bypass-dhcp"
	                                // "tun-ipv6"
	                                // "route-ipv6 2000::/3"
	                                // "redirect-gateway ipv6"
}

type OvpnAdmin struct {
	role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	serverConf             OvpnConfig
	clients                []OpenvpnClient
	activeClients          []clientStatus
	promRegistry           *prometheus.Registry
	mgmtInterfaces         map[string]string
	modules                []string
	mgmtStatusTimeFormat   string
	createUserMutex        *sync.Mutex
}

type OpenvpnServer struct {
	Host     string
	Port     string
	Protocol string
}

type openvpnClientConfig struct {
	Hosts      []OpenvpnServer
	CA         string
	Cert       string
	Key        string
	TLS        string
	PasswdAuth bool
}

type ccdRoute struct {
	Address     string `json:"address"`
	Mask        string `json:"mask"`
	Description string `json:"description"`
}

type Ccd struct {
	User          string     `json:"user"`
	ClientAddress string     `json:"clientAddress"`
	CustomRoutes  []ccdRoute `json:"customRoutes"`
	CustomIRoutes  []ccdRoute `json:"customIRoutes"`
}

type OpenvpnClient struct {
	Username          string `json:"username"`
	Identity          string `json:"identity"`
	Country           string `json:"country"`
	Province          string `json:"province"`
	City              string `json:"city"`
	Organisation      string `json:"organisation"`
	OrganisationUnit  string `json:"organisationUnit"`
	Email             string `json:"email"`
	ExpirationDate    string `json:"expirationDate"`
	RevocationDate    string `json:"revocationDate"`
	DeletionDate      string `json:"deletionDate"`
	flag              string
	SerialNumber      string `json:"serialNumber"`
	Filename          string `json:"filename"`

	ConnectionStatus  string `json:"connectionStatus"`
	Connections       []clientStatus `json:"connections"`
	AccountStatus     string `json:"accountStatus"`
}

type nodeInfo struct {
	Address  string `json:"address"`
	LastSeen string `json:"lastSeen"`
}
type network struct {
	Address  string `json:"address"`
	Netmask  string `json:"netmask"`
	LastSeen string `json:"lastSeen"`
}

type clientStatus struct {
	commonName              string
	connectedTo             string
	RealAddress             string `json:"realAddress"`
	BytesReceived           int64 `json:"bytesReceived"`
	BytesSent               int64 `json:"bytesSent"`
	ConnectedSince          string `json:"connectedSince"`
	VirtualAddress          string `json:"virtualAddress"`
	LastRef                 string `json:"lastRef"`
	Nodes                   []nodeInfo `json:"nodes"`
	Networks                []network `json:"networks"`
}

type AuthenticatePayload struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
}

type Roles struct {
	Openvpn bool `json:"openvpn"`
}

type Claims struct {
	jwt.StandardClaims
	Roles Roles `json:"roles"`
}

type Account struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
}

type AccountsFile struct {
	Users     []Account `json:"users"`
}

type MessagePayload struct {
	Message   string `json:"message"`
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

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
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
	oAdmin.clients = oAdmin.usersList()
	usersList, _ := json.Marshal(oAdmin.clients)
	fmt.Fprintf(w, "%s", usersList)
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
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
	_ = r.ParseForm()
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
	fmt.Fprintf(w, "%s", userStatistic)
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

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
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
	_ = r.ParseForm()
	if *authByPassword {
		passwordChanged, passwordChangeMessage := oAdmin.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		if passwordChanged {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ok", "message": "%s"}`, passwordChangeMessage)
			return
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"status":"error", "message": "%s"}`, passwordChangeMessage)
			return
		}
	} else {
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
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
	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	_ = r.ParseForm()
	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
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
	_ = r.ParseForm()
	ccd, _ := json.Marshal(oAdmin.getCcd(r.FormValue("username")))
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
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

	ccdApplied, applyStatus := oAdmin.modifyCcd(ccd)

	if ccdApplied {
		w.WriteHeader(http.StatusNoContent)
		fmt.Fprintf(w, applyStatus)
		return
	} else {
		json, _ := json.Marshal(MessagePayload{Message: applyStatus})
		http.Error(w, string(json), http.StatusUnprocessableEntity)
	}
}

func (oAdmin *OvpnAdmin) getUserProfile(username string) string {
	return fmt.Sprintf(`{"username":"%s"}`, username)
}

func (oAdmin *OvpnAdmin) showConfig(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}

	auth := getAuthCookie(r)
	ok, jwtUsername := jwtUsername(auth)
	user := ""
	if ok {
		user = fmt.Sprintf(`"user":%s,`, oAdmin.getUserProfile(jwtUsername))
	}

	fmt.Fprintf(w, `{%s"openvpn":{"url":""}}`, user)
}

func (oAdmin *OvpnAdmin) serverSettingsHandler(w http.ResponseWriter, r *http.Request) {
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
	enabledModules, enabledModulesErr := json.Marshal(oAdmin.modules)
	if enabledModulesErr != nil {
		log.Errorln(enabledModulesErr)
	}
	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s", "modules": %s }`, oAdmin.role, string(enabledModules))
}

func (oAdmin *OvpnAdmin) lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	fmt.Fprint(w, oAdmin.lastSyncTime)
}

func (oAdmin *OvpnAdmin) lastSuccessfulSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	fmt.Fprint(w, oAdmin.lastSuccessfulSyncTime)
}

func (oAdmin *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

func (oAdmin *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

func enableCors(w *http.ResponseWriter, r *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", (*r).Header.Get("Origin"))
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
}

var app OpenVPNPKI

func main() {
	kingpin.Version(version)
	kingpin.Parse()

	log.Printf("PATH %s\n", os.Getenv("PATH"))

	log.SetLevel(logLevels[*logLevel])
	log.SetFormatter(logFormats[*logFormat])

	if *storageBackend == "kubernetes.secrets" {
		err := app.run()
		if err != nil {
			log.Error(err)
		}
	}

	if *indexTxtPath == "" {
		*indexTxtPath = *easyrsaDirPath + "/pki/index.txt"
	}

	ovpnAdmin := new(OvpnAdmin)

	ovpnAdmin.lastSyncTime = "unknown"
	ovpnAdmin.role = *serverRole
	ovpnAdmin.lastSuccessfulSyncTime = "unknown"
	ovpnAdmin.masterSyncToken = *masterSyncToken
	ovpnAdmin.promRegistry = prometheus.NewRegistry()
	ovpnAdmin.modules = []string{}
	ovpnAdmin.createUserMutex = &sync.Mutex{}
	ovpnAdmin.mgmtInterfaces = make(map[string]string)
	ovpnAdmin.parseServerConf(*serverConfFile)
	ovpnAdmin.writeConfig(fmt.Sprintf("%s.test", *serverConfFile))

	log.Printf("management is %v | %v | %v", mgmtAddress, *mgmtAddress, len(*mgmtAddress))
	if mgmtAddress == nil || len(*mgmtAddress) == 0 || len((*mgmtAddress)[0]) == 0 {
		*mgmtAddress = []string{"main="+strings.Replace(ovpnAdmin.serverConf.management, " ", ":", 1)}
		log.Printf("management set to %v", *mgmtAddress)
	}

	for _, mgmtInterface := range *mgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.mgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	if len(ovpnAdmin.serverConf.clientConfigDir) > 0 {
		*ccdEnabled = true
		*ccdDir = absolutizePath(*serverConfFile, ovpnAdmin.serverConf.clientConfigDir)
		log.Printf("ccd dir set to %s", *ccdDir)
	}

	log.Printf("server conf %v", ovpnAdmin.serverConf.server)
	log.Printf("openvpnNetwork %v", *openvpnNetwork)
	if (openvpnNetwork == nil || len(*openvpnNetwork) == 0) && len(ovpnAdmin.serverConf.server) > 0 {
		*openvpnNetwork = convertNetworkMaskCidr(ovpnAdmin.serverConf.server)
		log.Printf("network set to %s", *openvpnNetwork)
	}

	ovpnAdmin.mgmtSetTimeFormat()

	ovpnAdmin.registerMetrics()
	ovpnAdmin.setState()

	go ovpnAdmin.updateState()

	if *masterBasicAuthPassword != "" && *masterBasicAuthUser != "" {
		ovpnAdmin.masterHostBasicAuth = true
	} else {
		ovpnAdmin.masterHostBasicAuth = false
	}

	ovpnAdmin.modules = append(ovpnAdmin.modules, "core")

	if *authByPassword {
		if *storageBackend != "kubernetes.secrets" {
			ovpnAdmin.modules = append(ovpnAdmin.modules, "passwdAuth")
		} else {
			log.Fatal("Right now the keys `--storage.backend=kubernetes.secret` and `--auth.password` are not working together. Please use only one of them ")
		}
	}

	if *ccdEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ccd")
	}

	if ovpnAdmin.role == "slave" {
		ovpnAdmin.syncDataFromMaster()
		go ovpnAdmin.syncWithMaster()
	}

	staticDir, _ := fs.Sub(content, "frontend/static")
	http.Handle("/", http.FileServer(http.FS(staticDir)))
	http.HandleFunc("/api/config", ovpnAdmin.showConfig)
	http.HandleFunc("/api/authenticate", ovpnAdmin.authenticate)
	http.HandleFunc("/api/logout", ovpnAdmin.logout)
	http.HandleFunc("/api/server/settings", ovpnAdmin.serverSettingsHandler)
	http.HandleFunc("/api/users/list", ovpnAdmin.userListHandler)
	http.HandleFunc("/api/user/create", ovpnAdmin.userCreateHandler)
	http.HandleFunc("/api/user/change-password", ovpnAdmin.userChangePasswordHandler)
	http.HandleFunc("/api/user/rotate", ovpnAdmin.userRotateHandler)
	http.HandleFunc("/api/user/delete", ovpnAdmin.userDeleteHandler)
	http.HandleFunc("/api/user/revoke", ovpnAdmin.userRevokeHandler)
	http.HandleFunc("/api/user/unrevoke", ovpnAdmin.userUnrevokeHandler)
	http.HandleFunc("/api/user/config/show", ovpnAdmin.userShowConfigHandler)
	http.HandleFunc("/api/user/disconnect", ovpnAdmin.userDisconnectHandler)
	http.HandleFunc("/api/user/statistic", ovpnAdmin.userStatisticHandler)
	http.HandleFunc("/api/user/ccd", ovpnAdmin.userShowCcdHandler)
	http.HandleFunc("/api/user/ccd/apply", ovpnAdmin.userApplyCcdHandler)

	http.HandleFunc("/api/sync/last/try", ovpnAdmin.lastSyncTimeHandler)
	http.HandleFunc("/api/sync/last/successful", ovpnAdmin.lastSuccessfulSyncTimeHandler)
	http.HandleFunc(downloadCertsApiUrl, ovpnAdmin.downloadCertsHandler)
	http.HandleFunc(downloadCcdApiUrl, ovpnAdmin.downloadCcdHandler)

	http.Handle(*metricsPath, promhttp.HandlerFor(ovpnAdmin.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})

	log.Printf("Bind: http://%s:%s", *listenHost, *listenPort)
	log.Fatal(http.ListenAndServe(*listenHost+":"+*listenPort, nil))
}

func convertNetworkMaskCidr(networkMask string) string {
	parts := strings.Fields(networkMask)
	pref := ipaddr.NewIPAddressString(parts[1]).GetAddress().GetBlockMaskPrefixLen(true)
	return fmt.Sprintf("%s/%d", parts[0], pref.Len())
}

func CacheControlWrapper(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=2592000") // 30 days
		h.ServeHTTP(w, r)
	})
}

func (oAdmin *OvpnAdmin) registerMetrics() {
	oAdmin.promRegistry.MustRegister(ovpnServerCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnServerCaCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientsTotal)
	oAdmin.promRegistry.MustRegister(ovpnClientsRevoked)
	oAdmin.promRegistry.MustRegister(ovpnClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnUniqClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnClientsExpired)
	oAdmin.promRegistry.MustRegister(ovpnClientCertificateExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionInfo)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionFrom)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesReceived)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesSent)
}

func (oAdmin *OvpnAdmin) setState() {
	oAdmin.activeClients = oAdmin.mgmtGetActiveClients()
	oAdmin.clients = oAdmin.usersList()

	ovpnServerCaCertExpire.Set(float64((getOvpnCaCertExpireDate().Unix() - time.Now().Unix()) / 3600 / 24))
}

func (oAdmin *OvpnAdmin) updateState() {
	for {
		time.Sleep(time.Duration(28) * time.Second)
		ovpnClientBytesSent.Reset()
		ovpnClientBytesReceived.Reset()
		ovpnClientConnectionFrom.Reset()
		ovpnClientConnectionInfo.Reset()
		ovpnClientCertificateExpire.Reset()
		go oAdmin.setState()
	}
}

func (oAdmin *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTpl, clientConfigTplErr := templates.ReadFile("templates/client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Error("clientConfigTpl not found in templates box")
		}
		return template.Must(template.New("client-config").Parse(string(clientConfigTpl)))
	}
}

func (oAdmin *OvpnAdmin) renderClientConfig(username string) string {
	_, _, err := checkUserExist(username)
	if err != nil {
		log.Warnf("user \"%s\" not found", username)
		return fmt.Sprintf("user \"%s\" not found", username)
	}
	var hosts []OpenvpnServer

	for _, server := range *openvpnServer {
		parts := strings.SplitN(server, ":", 3)
		l := len(parts)
		if l > 2 {
			hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1], Protocol: parts[2]})
		} else {
			hosts = append(hosts, OpenvpnServer{Host: parts[0], Port: parts[1]})
		}
	}

	if *openvpnServerBehindLB {
		var err error
		hosts, err = getOvpnServerHostsFromKubeApi()
		if err != nil {
			log.Error(err)
		}
	}

	log.Tracef("hosts for %s\n %v", username, hosts)

	conf := openvpnClientConfig{}
	conf.Hosts = hosts
	conf.CA = fRead(*easyrsaDirPath + "/pki/ca.crt")
	conf.TLS = fRead(*easyrsaDirPath + "/pki/ta.key")

	if *storageBackend == "kubernetes.secrets" {
		conf.Cert, conf.Key = app.easyrsaGetClientCert(username)
	} else {
		conf.Cert = fRead(*easyrsaDirPath + "/pki/issued/" + username + ".crt")
		conf.Key = fRead(*easyrsaDirPath + "/pki/private/" + username + ".key")
	}

	conf.PasswdAuth = *authByPassword

	t := oAdmin.getClientConfigTemplate()

	var tmp bytes.Buffer
	err = t.Execute(&tmp, conf)
	if err != nil {
		log.Errorf("something goes wrong during rendering config for %s", username)
		log.Debugf("rendering config for %s failed with error %v", username, err)
	}

	hosts = nil

	log.Tracef("Rendered config for user %s: %+v", username, tmp.String())

	return fmt.Sprintf("%+v", tmp.String())
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

func (oAdmin *OvpnAdmin) usersList() []OpenvpnClient {
	var users = make([]OpenvpnClient, 0)

	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()

	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		//match := re.FindStringSubmatch(line.Identity)
		//log.Debugf("match %s in %s", username, line.Identity)
		if line.Username != "server" && line.flag != "D" {
			totalCerts += 1
			switch {
				case line.flag == "V":
					validCerts += 1
				case line.flag == "R":
					revokedCerts += 1
				case line.flag == "E":
					expiredCerts += 1
			}

			ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(stringDateFormat, line.ExpirationDate) - apochNow) / 3600 / 24))
			line.Connections = getUserConnections(line.Username, oAdmin.activeClients)
			users = append(users, line)

		} else {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(stringDateFormat, line.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Warnf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))

	return users
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

func (oAdmin *OvpnAdmin) getUserStatistic(username string) []clientStatus {
	var userStatistic []clientStatus
	for _, u := range oAdmin.activeClients {
		if u.commonName == username {
			userStatistic = append(userStatistic, u)
		}
	}
	return userStatistic
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

	oAdmin.setState()
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

func (oAdmin *OvpnAdmin) mgmtRead(conn net.Conn) string {
	recvData := make([]byte, 32768)
	var out string
	var n int
	var err error
	for {
		n, err = conn.Read(recvData)
		if n <= 0 || err != nil {
			break
		} else {
			out += string(recvData[:n])
			if strings.Contains(out, "type 'help' for more info") || strings.Contains(out, "END") || strings.Contains(out, "SUCCESS:") || strings.Contains(out, "ERROR:") {
				break
			}
		}
	}
	return out
}

func (oAdmin *OvpnAdmin) mgmtConnectedUsersParser(text, serverName string) []clientStatus {
	var u = make([]clientStatus, 0)
	isClientList := false
	isRouteTable := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		txt := scanner.Text()
		if regexp.MustCompile(`^Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since$`).MatchString(txt) {
			isClientList = true
			continue
		}
		if regexp.MustCompile(`^ROUTING TABLE$`).MatchString(txt) {
			isClientList = false
			continue
		}
		if regexp.MustCompile(`^Virtual Address,Common Name,Real Address,Last Ref$`).MatchString(txt) {
			isRouteTable = true
			continue
		}
		if regexp.MustCompile(`^GLOBAL STATS$`).MatchString(txt) {
			// isRouteTable = false // ineffectual assignment to isRouteTable (ineffassign)
			break
		}
		if isClientList {
			user := strings.Split(txt, ",")
			userName := user[0]
			userAddress := user[1]
			userBytesReceived := user[2]
			userBytesSent := user[3]
			userConnectedSince := user[4]
			bytesSent, _ := strconv.ParseInt(userBytesSent, 10, 64)
			bytesReceive, _ := strconv.ParseInt(userBytesReceived, 10, 64)

			userStatus := clientStatus{
				commonName:     userName,
				RealAddress:    userAddress,
				BytesReceived:  bytesReceive,
				BytesSent:      bytesSent,
				ConnectedSince: userConnectedSince,
				connectedTo:    serverName,
			}
			u = append(u, userStatus)
			ovpnClientConnectionFrom.WithLabelValues(userName, userAddress).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, userConnectedSince)))
			ovpnClientBytesSent.WithLabelValues(userName).Set(float64(bytesSent))
			ovpnClientBytesReceived.WithLabelValues(userName).Set(float64(bytesReceive))
		}
		if isRouteTable {
			user := strings.Split(txt, ",")
			peerAddress := user[0]
			userName := user[1]
			realAddress := user[2]
			userConnectedSince := user[3]

			for i := range u {
				if u[i].commonName == userName && u[i].RealAddress == realAddress {
					if strings.HasSuffix(peerAddress, "C") {
						u[i].Nodes = append(u[i].Nodes, nodeInfo{Address: peerAddress[:len(peerAddress)-1], LastSeen: userConnectedSince})
					} else if strings.Contains(peerAddress, "/") {
						u[i].Networks = append(u[i].Networks, network{Address: peerAddress, LastSeen: userConnectedSince})
					} else {

						u[i].VirtualAddress = peerAddress
						u[i].LastRef = userConnectedSince
					}
					ovpnClientConnectionInfo.WithLabelValues(user[1], user[0]).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, user[3])))
					break
				}
			}
		}
	}
	return u
}

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(serverName clientStatus) {
	conn, err := net.Dial("tcp", oAdmin.mgmtInterfaces[serverName.connectedTo])
	if err != nil {
		log.Errorf("openvpn mgmt interface for %s is not reachable by addr %s", serverName.connectedTo, oAdmin.mgmtInterfaces[serverName.connectedTo])
		return
	}
	oAdmin.mgmtRead(conn) // read welcome message
	conn.Write([]byte(fmt.Sprintf("kill %s\n", serverName.commonName)))
	fmt.Printf("%v", oAdmin.mgmtRead(conn))
	conn.Close()
}

func (oAdmin *OvpnAdmin) mgmtGetActiveClients() []clientStatus {
	var activeClients []clientStatus

	for srv, addr := range oAdmin.mgmtInterfaces {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Warnf("openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			break
		}
		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("status\n"))
		activeClients = append(activeClients, oAdmin.mgmtConnectedUsersParser(oAdmin.mgmtRead(conn), srv)...)
		conn.Close()
	}
	return activeClients
}

func (oAdmin *OvpnAdmin) mgmtSetTimeFormat() {
	// time format for version 2.5 and may be newer
	oAdmin.mgmtStatusTimeFormat = "2006-01-02 15:04:05"
	log.Debugf("mgmtStatusTimeFormat: %s", oAdmin.mgmtStatusTimeFormat)

	type serverVersion struct {
		name    string
		version string
	}

	var serverVersions []serverVersion

	for srv, addr := range oAdmin.mgmtInterfaces {

		var conn net.Conn
		var err error
		for connAttempt := 0; connAttempt < 10; connAttempt++ {
			conn, err = net.Dial("tcp", addr)
			if err == nil {
				log.Debugf("mgmtSetTimeFormat: successful connection to %s/%s", srv, addr)
				break
			}
			log.Warnf("mgmtSetTimeFormat: openvpn mgmt interface for %s is not reachable by addr %s", srv, addr)
			time.Sleep(time.Duration(2) * time.Second)
		}
		if err != nil {
			break
		}

		oAdmin.mgmtRead(conn) // read welcome message
		conn.Write([]byte("version\n"))
		out := oAdmin.mgmtRead(conn)
		conn.Close()

		log.Trace(out)

		for _, s := range strings.Split(out, "\n") {
			if strings.Contains(s, "OpenVPN Version:") {
				serverVersions = append(serverVersions, serverVersion{srv, strings.Split(s, " ")[3]})
				break
			}
		}
	}

	if len(serverVersions) == 0 {
		return
	}

	firstVersion := serverVersions[0].version

	if strings.HasPrefix(firstVersion, "2.4") {
		oAdmin.mgmtStatusTimeFormat = time.ANSIC
		log.Debugf("mgmtStatusTimeFormat changed: %s", oAdmin.mgmtStatusTimeFormat)
	}

	warn := ""
	for _, v := range serverVersions {
		if firstVersion != v.version {
			warn = "mgmtSetTimeFormat: servers have different versions of openvpn, user connection status may not work"
			log.Warn(warn)
			break
		}
	}

	if warn != "" {
		for _, v := range serverVersions {
			log.Infof("server name: %s, version: %s", v.name, v.version)
		}
	}
}

func getUserConnections(username string, connectedUsers []clientStatus) []clientStatus {
	var connections []clientStatus
	for _, connectedUser := range connectedUsers {
		if connectedUser.commonName == username {
			connections = append(connections, connectedUser)
		}
	}
	return connections
}

func isUserConnected(username string, connectedUsers []clientStatus) (bool, []clientStatus) {
	var connections []clientStatus = make([]clientStatus, 0)
	var connected = false

	for _, connectedUser := range connectedUsers {
		if connectedUser.commonName == username {
			connected = true
			connections = append(connections, connectedUser)
		}
	}
	return connected, connections
}

func (oAdmin *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		err := fDelete(certsArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(certsArchivePath, *masterHost+downloadCertsApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		err := fDelete(ccdArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(ccdArchivePath, *masterHost+downloadCcdApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
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

func (oAdmin *OvpnAdmin) syncDataFromMaster() {
	retryCountMax := 3
	certsDownloadFailed := true
	ccdDownloadFailed := true

	for certsDownloadRetries := 0; certsDownloadRetries < retryCountMax; certsDownloadRetries++ {
		log.Infof("Downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		if oAdmin.downloadCerts() {
			certsDownloadFailed = false
			log.Info("Decompressing archive with certificates from master")
			unArchiveCerts()
			log.Info("Decompression archive with certificates from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		}
	}

	for ccdDownloadRetries := 0; ccdDownloadRetries < retryCountMax; ccdDownloadRetries++ {
		log.Infof("Downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		if oAdmin.downloadCcd() {
			ccdDownloadFailed = false
			log.Info("Decompressing archive with ccd from master")
			unArchiveCcd()
			log.Info("Decompression archive with ccd from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		}
	}

	oAdmin.lastSyncTime = time.Now().Format(stringDateFormat)
	if !ccdDownloadFailed && !certsDownloadFailed {
		oAdmin.lastSuccessfulSyncTime = time.Now().Format(stringDateFormat)
	}
}

func (oAdmin *OvpnAdmin) syncWithMaster() {
	for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		oAdmin.syncDataFromMaster()
	}
}

func getOvpnServerHostsFromKubeApi() ([]OpenvpnServer, error) {
	var hosts []OpenvpnServer
	var lbHost string

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("%s", err.Error())
	}

	for _, serviceName := range *openvpnServiceName {
		service, err := clientset.CoreV1().Services(fRead(kubeNamespaceFilePath)).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			log.Error(err)
		}

		log.Tracef("service from kube api %v", service)
		log.Tracef("service.Status from kube api %v", service.Status)
		log.Tracef("service.Status.LoadBalancer from kube api %v", service.Status.LoadBalancer)

		lbIngress := service.Status.LoadBalancer.Ingress
		if len(lbIngress) > 0 {
			if lbIngress[0].Hostname != "" {
				lbHost = lbIngress[0].Hostname
			}

			if lbIngress[0].IP != "" {
				lbHost = lbIngress[0].IP
			}
		}

		hosts = append(hosts, OpenvpnServer{lbHost, strconv.Itoa(int(service.Spec.Ports[0].Port)), strings.ToLower(string(service.Spec.Ports[0].Protocol))})
	}

	if len(hosts) == 0 {
		return []OpenvpnServer{{Host: "kubernetes services not found"}}, err
	}

	return hosts, nil
}

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *easyrsaDirPath + "/pki/ca.crt"
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("error read file %s: %s", caCertPath, err.Error())
	}

	certPem, _ := pem.Decode(caCert)
	certPemBytes := certPem.Bytes

	cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Errorf("error parse certificate ca.crt: %s", err.Error())
		return time.Now()
	}

	return cert.NotAfter
}

// https://community.openvpn.net/openvpn/ticket/623
func chmodFix() {
	err := os.Chmod(*easyrsaDirPath+"/pki", 0755)
	if err != nil {
		log.Error(err)
	}
	err = os.Chmod(*easyrsaDirPath+"/pki/crl.pem", 0644)
	if err != nil {
		log.Error(err)
	}
}

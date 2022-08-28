package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"

	"io/fs"
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


	log "github.com/sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"gopkg.in/alecthomas/kingpin.v2"
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
	jwtSecretFile  = kingpin.Flag("jwt.secret", "jwt secret file").Default("jwt.secret.key").Envar("JWT_SECRET").String()
	ovpnConfigFile = kingpin.Flag("admin.accounts", "Admin accounts files").Default("admin-accounts.json").Envar("ADMIN_ACCOUNT").String()

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

//go:embed templates/*
var templates embed.FS
//go:embed frontend/static
var content embed.FS

type OvpnAdmin struct {
	role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	serverConf             OvpnConfig
	clients                []OpenvpnClient
	activeClients          []ClientStatus
	promRegistry           *prometheus.Registry
	mgmtInterfaces         map[string]string
	modules                []string
	mgmtStatusTimeFormat   string
	createUserMutex        *sync.Mutex
	masterCn               string
	applicationPreferences ApplicationConfig
}

type OpenvpnServer struct {
	Host     string
	Port     string
	Protocol string
}

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

	ConnectionStatus  string         `json:"connectionStatus"`
	Connections       []ClientStatus `json:"connections"`
	AccountStatus     string         `json:"accountStatus"`
}

type NodeInfo struct {
	Address  string `json:"address"`
	LastSeen string `json:"lastSeen"`
}
type Network struct {
	Address  string `json:"address"`
	Netmask  string `json:"netmask"`
	LastSeen string `json:"lastSeen"`
}

type ClientStatus struct {
	commonName              string
	connectedTo             string
	RealAddress             string `json:"realAddress"`
	BytesReceived           int64 `json:"bytesReceived"`
	BytesSent               int64 `json:"bytesSent"`
	ConnectedSince          string `json:"connectedSince"`
	VirtualAddress          string `json:"virtualAddress"`
	LastRef                 string     `json:"lastRef"`
	Nodes                   []NodeInfo `json:"nodes"`
	Networks                []Network  `json:"networks"`
}

type Roles struct {
	Openvpn bool `json:"openvpn"`
}

type Claims struct {
	jwt.StandardClaims
	Roles Roles `json:"roles"`
}

type MessagePayload struct {
	Message   string `json:"message"`
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

func (oAdmin *OvpnAdmin) restartServer() error {
	_, err := runBash(*serverRestartCommand)
	return err
}

//func (oAdmin *OvpnAdmin) serverSettingsHandler(w http.ResponseWriter, r *http.Request) {
//	log.Info(r.RemoteAddr, " ", r.RequestURI)
//	enableCors(&w, r)
//	if (*r).Method == "OPTIONS" {
//		return
//	}
//	auth := getAuthCookie(r)
//	if hasReadRole := jwtHasReadRole(auth); !hasReadRole {
//		w.WriteHeader(http.StatusForbidden)
//		return
//	}
//	enabledModules, enabledModulesErr := json.Marshal(oAdmin.modules)
//	if enabledModulesErr != nil {
//		log.Errorln(enabledModulesErr)
//	}
//	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s", "modules": %s }`, oAdmin.role, string(enabledModules))
//}

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
	ovpnAdmin.writeConfig(fmt.Sprintf("%s.test", *serverConfFile), ovpnAdmin.serverConf)
	ovpnAdmin.applicationPreferences = loadConfig()

	if mgmtAddress == nil || len(*mgmtAddress) == 0 || len((*mgmtAddress)[0]) == 0 {
		*mgmtAddress = []string{"main="+strings.Replace(ovpnAdmin.serverConf.management, " ", ":", 1)}
	}

	for _, mgmtInterface := range *mgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.mgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	if len(ovpnAdmin.serverConf.clientConfigDir) > 0 {
		*ccdEnabled = true
		*ccdDir = absolutizePath(*serverConfFile, ovpnAdmin.serverConf.clientConfigDir)
	}

	if (openvpnNetwork == nil || len(*openvpnNetwork) == 0) && len(ovpnAdmin.serverConf.server) > 0 {
		*openvpnNetwork = convertNetworkMaskCidr(ovpnAdmin.serverConf.server)
	}

	if len(ovpnAdmin.serverConf.cert) > 0 {
		ovpnAdmin.masterCn = ovpnAdmin.getCommonNameFromCertificate(absolutizePath(*serverConfFile, ovpnAdmin.serverConf.cert))
	}

	ovpnAdmin.mgmtSetTimeFormat()

	ovpnAdmin.registerMetrics()
	ovpnAdmin.setState()

	go ovpnAdmin.updateState()

	ovpnAdmin.masterHostBasicAuth = *masterBasicAuthPassword != "" && *masterBasicAuthUser != ""

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
	embedFs := http.FS(staticDir)
	http.HandleFunc("/api/config", ovpnAdmin.showConfig)
	http.HandleFunc("/api/config/settings/save", ovpnAdmin.saveConfigSettings)
	http.HandleFunc("/api/config/preferences/save", ovpnAdmin.saveConfigPreferences)
	http.HandleFunc("/api/config/admin/", ovpnAdmin.saveAdminAccount)
	http.HandleFunc("/api/authenticate", ovpnAdmin.authenticate)
	http.HandleFunc("/api/logout", ovpnAdmin.logout)
	//http.HandleFunc("/api/server/settings", ovpnAdmin.serverSettingsHandler)
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
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ovpnAdmin.catchAll(embedFs, w, r)
	})

	log.Printf("Bind: http://%s:%s", *listenHost, *listenPort)
	log.Fatal(http.ListenAndServe(*listenHost+":"+*listenPort, nil))
}

func (oAdmin *OvpnAdmin) catchAll(embedFs http.FileSystem, w http.ResponseWriter, r *http.Request) {
	_, err := embedFs.Open(r.URL.Path)
	if err != nil {
		r.URL.Path = "/"
	}

	httpFS := http.FileServer(embedFs)
	httpFS.ServeHTTP(w, r)
}

func (oAdmin *OvpnAdmin) setState() {
	oAdmin.activeClients = oAdmin.mgmtGetActiveClients()
	oAdmin.clients = oAdmin.usersList()

	ovpnServerCaCertExpire.Set(float64((oAdmin.getExpireDateFromCertificate(absolutizePath(*serverConfFile, oAdmin.serverConf.ca)).Unix() - time.Now().Unix()) / 3600 / 24))
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
		if line.Username != oAdmin.masterCn && line.flag != "D" {
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


func (oAdmin *OvpnAdmin) getUserStatistic(username string) []ClientStatus {
	var userStatistic []ClientStatus
	for _, u := range oAdmin.activeClients {
		if u.commonName == username {
			userStatistic = append(userStatistic, u)
		}
	}
	return userStatistic
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

func (oAdmin *OvpnAdmin) mgmtConnectedUsersParser(text, serverName string) []ClientStatus {
	var u = make([]ClientStatus, 0)
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

			userStatus := ClientStatus{
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
						u[i].Nodes = append(u[i].Nodes, NodeInfo{Address: peerAddress[:len(peerAddress)-1], LastSeen: userConnectedSince})
					} else if strings.Contains(peerAddress, "/") {
						u[i].Networks = append(u[i].Networks, Network{Address: peerAddress, LastSeen: userConnectedSince})
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

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(serverName ClientStatus) {
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

func (oAdmin *OvpnAdmin) mgmtGetActiveClients() []ClientStatus {
	var activeClients []ClientStatus

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

func getUserConnections(username string, connectedUsers []ClientStatus) []ClientStatus {
	var connections []ClientStatus
	for _, connectedUser := range connectedUsers {
		if connectedUser.commonName == username {
			connections = append(connections, connectedUser)
		}
	}
	return connections
}

func isUserConnected(username string, connectedUsers []ClientStatus) (bool, []ClientStatus) {
	var connections = make([]ClientStatus, 0)
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

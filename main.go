package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"math/rand"

	"io/fs"
	"embed"
	"net"
	"net/http"
	"os"
	"regexp"
	//"strconv"
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
	usernameRegexp       = `^([a-zA-Z0-9_.\-@])+$`
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
	serverConfFile           = kingpin.Flag("server.conf", "Configuration file for the server").Default("/etc/openvpn/server.conf").Envar("OPENVPN_SERVER_CONF").String()
	serverRestartCommand     = kingpin.Flag("restart.cmd", "Command to restart the server").Default("systemctl restart openvpn@server.service").Envar("OPENVPN_RESTART_CMD").String()
	listenHost               = kingpin.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort               = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8042").Envar("OVPN_LISTEN_PORT").String()
	masterHost               = kingpin.Flag("master.host", "URL for the master server").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	masterSyncToken          = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	openvpnNetwork           = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("").Envar("OVPN_NETWORK").String()
	openvpnServer            = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	mgmtAddress              = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface; can have multiple values").Default("").Envar("OPENVPN_MANAGEMENT").String()
	metricsPath              = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaDirPath           = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("/usr/share/easy-rsa/").Envar("EASYRSA_PATH").String()
	indexTxtPath             = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file").Default("").Envar("EASYRSA_INDEX_PATH").String()
	ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	logLevel                 = kingpin.Flag("log.level", "set log level: trace, debug, info, warn, error (default info)").Default("info").Envar("LOG_LEVEL").String()
	logFormat                = kingpin.Flag("log.format", "set log format: text, json (default text)").Default("text").Envar("LOG_FORMAT").String()
	storageBackend           = kingpin.Flag("storage.backend", "storage backend: filesystem, kubernetes.secrets (default filesystem)").Default("filesystem").Envar("STORAGE_BACKEND").String()
	jwtSecretFile            = kingpin.Flag("jwt.secret", "jwt secret file").Default("").Envar("JWT_SECRET").String()
	ovpnConfigFile           = kingpin.Flag("admin.accounts", "Admin accounts files").Default("/etc/openvpn/admin-config.json").Envar("ADMIN_ACCOUNT").String()

	certsArchivePath = "/tmp/" + certsArchiveFileName
	ccdArchivePath   = "/tmp/" + ccdArchiveFileName

	upgrader = websocket.Upgrader{} // use default options
	logLevels = map[string]log.Level{
		"trace": log.TraceLevel,
		"debug": log.DebugLevel,
		"info":  log.InfoLevel,
		"warn":  log.WarnLevel,
		"error": log.ErrorLevel,
	}
	logFormats = map[string]log.Formatter{
		"text": &log.TextFormatter{},
		"json": &log.JSONFormatter{},
	}

)
var version string

//go:embed templates/*
var templates embed.FS
//go:embed frontend/static
var content embed.FS

type WsSafeConn struct {
	ws      *websocket.Conn
	mu      sync.Mutex
	last    time.Time
	next    *time.Timer
	streams []string
}

type OvpnAdmin struct {
	//role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	serverConf             OvpnConfig
	clients                []*OpenvpnClient
	activeConnections      []*ClientStatus
	promRegistry           *prometheus.Registry
	mgmtInterface          string
	createUserMutex        *sync.Mutex
	conn                   net.Conn
	waitingCommands        []WaitingCommand
	mgmtBuffer             []string
	updatedUsers           []*OpenvpnClient
	masterCn               string
	applicationPreferences ApplicationConfig
	wsConnections          []*WsSafeConn
	outboundIp             net.IP
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

	ConnectionStatus  string          `json:"connectionStatus"`
	Connections       []*ClientStatus `json:"connections"`
	AccountStatus     string          `json:"accountStatus"`
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
	ClientId                int64 `json:"clientId"`
	commonName              string
	RealAddress             string `json:"realAddress"`
	BytesReceived           int64 `json:"bytesReceived"`
	BytesSent               int64 `json:"bytesSent"`
	SpeedBytesReceived      int64 `json:"speedBytesReceived"`
	SpeedBytesSent          int64 `json:"speedBytesSent"`
	lastByteReceived        time.Time
	ConnectedSince          string `json:"connectedSince"`
	VirtualAddress          string `json:"virtualAddress"`
	VirtualAddressIPv6      string `json:"virtualAddressIPv6"`
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

type ConnectionId struct {
	 ClientId   int64 `json:"clientId"`
}

func (oAdmin *OvpnAdmin) apiUserKill(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var req ConnectionId
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		jsonErr, _ := json.Marshal(MessagePayload{Message: "Cant parse JSON"})
		http.Error(w, string(jsonErr), http.StatusUnprocessableEntity)
		return
	}

	for _, c := range oAdmin.clients {
		for _, conn := range c.Connections {
			if conn.ClientId == req.ClientId {
				if err := oAdmin.killAndRemoveConnection(c, conn); err != nil {
					jsonErr, _ := json.Marshal(MessagePayload{Message: err.Error()})
					http.Error(w, string(jsonErr), http.StatusInternalServerError)
					return
				}
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	oAdmin.usersList()
	usersList, _ := json.Marshal(oAdmin.clients)
	_, _ = w.Write(usersList)
	//fmt.Fprintf(w, "%s", usersList)
}

//func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
//	log.Info(r.RemoteAddr, " ", r.RequestURI)
//	enableCors(&w, r)
//	if (*r).Method == "OPTIONS" {
//		return
//	}
//	auth := getAuthCookie(r)
//	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
//		w.WriteHeader(http.StatusForbidden)
//		return
//	}
//	_ = r.ParseForm()
//	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
//	fmt.Fprintf(w, "%s", userStatistic)
//}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	if *authByPassword {
		passwordChanged, passwordChangeMessage := oAdmin.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		if passwordChanged {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"message": "%s"}`, passwordChangeMessage)
			return
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"message": "%s"}`, passwordChangeMessage)
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
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(r.FormValue("username")))
}

//func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
//	log.Info(r.RemoteAddr, " ", r.RequestURI)
//	enableCors(&w, r)
//	if (*r).Method == "OPTIONS" {
//		return
//	}
//	_ = r.ParseForm()
//	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
//	fmt.Fprintf(w, "%s", r.FormValue("username"))
//}

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	ccd, _ := json.Marshal(oAdmin.getCcd(r.FormValue("username")))
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) restartServer() error {
	_, err := runBash(*serverRestartCommand)
	return err
}

func (oAdmin *OvpnAdmin) lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
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
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
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
	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	//if oAdmin.role == "slave" {
	//	http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
	//	return
	//}
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

func enableCors(w *http.ResponseWriter, r *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", (*r).Header.Get("Origin"))
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
}

var app OpenVPNPKI

func main() {
	rand.Seed(time.Now().UnixNano())
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

	oAdmin := new(OvpnAdmin)
	oAdmin.lastSyncTime = "unknown"
	//oAdmin.role = *serverRole
	oAdmin.lastSuccessfulSyncTime = "unknown"
	oAdmin.masterSyncToken = *masterSyncToken
	oAdmin.promRegistry = prometheus.NewRegistry()
	//oAdmin.modules = []string{}
	oAdmin.createUserMutex = &sync.Mutex{}
	oAdmin.mgmtInterface = *mgmtAddress
	oAdmin.parseServerConf(*serverConfFile)
	//oAdmin.writeConfig(fmt.Sprintf("%s.test", *serverConfFile), oAdmin.serverConf)
	oAdmin.loadPreferences()
	oAdmin.outboundIp = GetOutboundIP()
	//oAdmin.applicationPreferences.JwtSecretData = []byte(fRead(*jwtSecretFile))

	//log.Printf("mgmt interface %v", oAdmin.mgmtInterface)
	if len(oAdmin.mgmtInterface) == 0 {
		oAdmin.mgmtInterface = strings.Replace(oAdmin.serverConf.management, " ", ":", 1)
		//log.Printf("mgmt interface is now %v", oAdmin.mgmtInterface)
	}

	if len(oAdmin.serverConf.clientConfigDir) > 0 {
		*ccdDir = absolutizePath(*serverConfFile, oAdmin.serverConf.clientConfigDir)
	}

	if (openvpnNetwork == nil || len(*openvpnNetwork) == 0) && len(oAdmin.serverConf.server) > 0 {
		*openvpnNetwork = convertNetworkMaskCidr(oAdmin.serverConf.server)
	}

	if len(oAdmin.serverConf.cert) > 0 {
		cert := oAdmin.getCommonNameFromCertificate(absolutizePath(*serverConfFile, oAdmin.serverConf.cert))
		if cert != nil {
			oAdmin.masterCn = cert.Subject.CommonName
			ovpnServerCaCertExpire.Set(float64((cert.NotAfter.Unix() - time.Now().Unix()) / 3600 / 24))
		}
	}

	oAdmin.registerMetrics()

	if len(oAdmin.mgmtInterface) > 0 {
		go oAdmin.connectToManagementInterface()
	}

	//oAdmin.masterHostBasicAuth = *masterBasicAuthPassword != "" && *masterBasicAuthUser != ""

	upgrader.CheckOrigin = oAdmin.checkWebsocketOrigin
	upgrader.Subprotocols = []string{"ovpn"}
	oAdmin.usersList()

	staticDir, _ := fs.Sub(content, "frontend/static")
	embedFs := http.FS(staticDir)
	http.HandleFunc("/api/ws", oAdmin.websocket)
	http.HandleFunc("/api/config", oAdmin.showConfig)
	http.HandleFunc("/api/config/settings/save", oAdmin.postServerConfig)
	http.HandleFunc("/api/config/preferences/save", oAdmin.postPreferences)
	http.HandleFunc("/api/config/admin/", oAdmin.saveAdminAccount)
	http.HandleFunc("/api/authenticate", oAdmin.authenticate)
	http.HandleFunc("/api/logout", oAdmin.logout)
	//http.HandleFunc("/api/server/settings", oAdmin.serverSettingsHandler)
	http.HandleFunc("/api/users/list", oAdmin.userListHandler)
	http.HandleFunc("/api/user/create", oAdmin.userCreateHandler)
	http.HandleFunc("/api/user/change-password", oAdmin.userChangePasswordHandler)
	http.HandleFunc("/api/user/rotate", oAdmin.userRotateHandler)
	http.HandleFunc("/api/user/kill", oAdmin.apiUserKill)
	http.HandleFunc("/api/user/delete", oAdmin.userDeleteHandler)
	http.HandleFunc("/api/user/revoke", oAdmin.userRevokeHandler)
	http.HandleFunc("/api/user/unrevoke", oAdmin.userUnrevokeHandler)
	http.HandleFunc("/api/user/config/show", oAdmin.userShowConfigHandler)
	//http.HandleFunc("/api/user/disconnect", oAdmin.userDisconnectHandler)
	//http.HandleFunc("/api/user/statistic", oAdmin.userStatisticHandler)
	http.HandleFunc("/api/user/ccd", oAdmin.userShowCcdHandler)
	http.HandleFunc("/api/user/ccd/apply", oAdmin.userApplyCcdHandler)

	http.HandleFunc("/api/sync/last/try", oAdmin.lastSyncTimeHandler)
	http.HandleFunc("/api/sync/last/successful", oAdmin.lastSuccessfulSyncTimeHandler)
	http.HandleFunc(downloadCertsApiUrl, oAdmin.downloadCertsHandler)
	http.HandleFunc(downloadCcdApiUrl, oAdmin.downloadCcdHandler)

	http.Handle(*metricsPath, promhttp.HandlerFor(oAdmin.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		oAdmin.catchAll(embedFs, w, r)
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

func (oAdmin *OvpnAdmin) usersList() {
	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()
	clients := indexTxtParser(fRead(*indexTxtPath))
	oAdmin.clients = make([]*OpenvpnClient, 0)

	for _, line := range clients {
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
			oAdmin.clients = append(oAdmin.clients, line)

		} else {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(stringDateFormat, line.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	oAdmin.updateConnections(oAdmin.activeConnections)
	//line.Connections = getUserConnections(line.Username, oAdmin.activeClients)

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Warnf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))
}

func (oAdmin *OvpnAdmin) updateConnections(activeClients []*ClientStatus) {
	for _, client := range oAdmin.clients {
		client.Connections = getUserConnections(client.Username, activeClients)
	}
}

//func (oAdmin *OvpnAdmin) getUserStatistic(username string) []*ClientStatus {
//	var userStatistic = make([]*ClientStatus, 0)
//	for _, u := range oAdmin.activeClients {
//		if u.commonName == username {
//			userStatistic = append(userStatistic, u)
//		}
//	}
//	return userStatistic
//}


func getUserConnections(username string, connectedUsers []*ClientStatus) []*ClientStatus {
	var connections = make([]*ClientStatus, 0)
	for _, connectedUser := range connectedUsers {
		if connectedUser.commonName == username {
			connections = append(connections, connectedUser)
		}
	}
	return connections
}

func (oAdmin *OvpnAdmin) getUser(username string) *OpenvpnClient {
	for _, connectedUser := range oAdmin.clients {
		if connectedUser.Username == username {
			return connectedUser
		}
	}
	return nil
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

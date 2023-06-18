package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"math/rand"

	"embed"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

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
	jwtSecretFile            = kingpin.Flag("jwt.secret", "jwt secret file").Default("").Envar("JWT_SECRET").String()
	//ovpnConfigFile           = kingpin.Flag("admin.accounts", "Admin accounts files").Default("/etc/openvpn/admin-config.json").Envar("ADMIN_ACCOUNT").String()
	ovpnConfigDir            = kingpin.Flag("config.dir", "Configuration files dir").Default("/etc/openvpn/admin").Envar("CONFIG_DIR").String()

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
	ws              *websocket.Conn
	mu              sync.Mutex
	last            time.Time
	next            *time.Timer
	streams         []string
	role            string
	hello           Hello
	xForwardedFor   string
	xForwardedProto string
	userAgent       string
}

type OvpnAdmin struct {
	//role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	serverConf             OvpnConfig
	clients                []*ClientCertificate
	triggerUpdateChan      chan *ClientCertificate
	promRegistry           *prometheus.Registry
	mgmtInterface          string
	createUserMutex        *sync.Mutex
	conn                   net.Conn
	waitingCommands        []WaitingCommand
	mgmtBuffer             []string
	updatedUsers           []*ClientCertificate
	masterCn               string
	applicationPreferences ApplicationConfig
	wsConnections          []*WsSafeConn
	outboundIp             net.IP
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

func (app *OvpnAdmin) restartServer() error {
	_, err := runBash(*serverRestartCommand)
	return err
}

func enableCors(w *http.ResponseWriter, r *http.Request) {
	// TODO: manage whitelist of origins
	(*w).Header().Set("Access-Control-Allow-Origin", (*r).Header.Get("Origin"))
	(*w).Header().Set("Access-Control-Allow-Credentials", "true")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
}

var app OvpnAdmin

func main() {
	rand.Seed(time.Now().UnixNano())
	kingpin.Version(version)
	kingpin.Parse()

	log.Printf("PATH %s\n", os.Getenv("PATH"))

	log.SetLevel(logLevels[*logLevel])
	log.SetFormatter(logFormats[*logFormat])

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

	upgrader.CheckOrigin = oAdmin.checkWebsocketOrigin
	upgrader.Subprotocols = []string{"ovpn"}
	oAdmin.updateClientList(indexTxtParser(fRead(*indexTxtPath)))
	oAdmin.triggerUpdateChan = make(chan *ClientCertificate)
	go oAdmin.autoUpdate()

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
	http.HandleFunc("/api/user/kill", oAdmin.apiConnectionKill)
	http.HandleFunc("/api/user/delete", oAdmin.userDeleteHandler)
	http.HandleFunc("/api/user/revoke", oAdmin.userRevokeHandler)
	http.HandleFunc("/api/user/unrevoke", oAdmin.userUnrevokeHandler)
	http.HandleFunc("/api/user/config/show", oAdmin.userShowConfigHandler)
	//http.HandleFunc("/api/user/disconnect", oAdmin.userDisconnectHandler)
	//http.HandleFunc("/api/user/statistic", oAdmin.userStatisticHandler)
	http.HandleFunc("/api/user/ccd", oAdmin.userShowCcdHandler)
	http.HandleFunc("/api/user/ccd/apply", oAdmin.userApplyCcdHandler)
	http.HandleFunc("/api/node/", oAdmin.handleReadNodeConfig)

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

func (app *OvpnAdmin) catchAll(embedFs http.FileSystem, w http.ResponseWriter, r *http.Request) {
	_, err := embedFs.Open(r.URL.Path)
	if err != nil {
		r.URL.Path = "/"
	}

	httpFS := http.FileServer(embedFs)
	httpFS.ServeHTTP(w, r)
}

//func (app *OvpnAdmin) handleHelloAction(conn *WsSafeConn, packet WebsocketAction, hello Hello) {
//	//rawJson, _ := json.Marshal(hello)
//	//log.Printf("storing hello for %s: %s", conn, rawJson)
//
//	client, rpic := app.findConnection(conn)
//	if rpic == nil {
//		return
//	}
//	rpic.Hello = &hello
//	app.triggerBroadcastUser(client)
//}

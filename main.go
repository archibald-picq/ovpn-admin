package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"math/rand"
	"rpiadm/backend/mgmt"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/preference"
	"rpiadm/backend/rpi"
	"rpiadm/backend/shell"

	"embed"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	stringDateFormat = "2006-01-02 15:04:05"
)

var (
	serverConfFile       = kingpin.Flag("server.conf", "Configuration file for the server").Default("/etc/openvpn/server.conf").Envar("OPENVPN_SERVER_CONF").String()
	serverRestartCommand = kingpin.Flag("restart.cmd", "Command to restart the server").Default("systemctl restart openvpn@server.service").Envar("OPENVPN_RESTART_CMD").String()
	listenHost           = kingpin.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort           = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8042").Envar("OVPN_LISTEN_PORT").String()
	masterHost           = kingpin.Flag("master.host", "URL for the master server").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	masterSyncToken      = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	//openvpnNetwork       = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("").Envar("OVPN_NETWORK").String()
	openvpnServer  = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	mgmtAddress    = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface; can have multiple values").Default("").Envar("OPENVPN_MANAGEMENT").String()
	metricsPath    = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaBinPath = kingpin.Flag("easyrsa.bin", "path to easyrsa dir").Default("/usr/share/easy-rsa/easyrsa").Envar("EASYRSA_BIN").String()
	easyrsaDirPath = kingpin.Flag("easyrsa.path", "path to easyrsa config").Default("/etc/openvpn/easyrsa").Envar("EASYRSA_DIR").String()
	//ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	jwtSecretFile            = kingpin.Flag("jwt.secret", "jwt secret file").Default("").Envar("JWT_SECRET").String()
	ovpnConfigDir            = kingpin.Flag("config.dir", "Configuration files dir").Default("/etc/openvpn/admin").Envar("CONFIG_DIR").String()

	upgrader = websocket.Upgrader{} // use default options
	//logLevels = map[string]log.Level{
	//	"trace": log.TraceLevel,
	//	"debug": log.DebugLevel,
	//	"info":  log.InfoLevel,
	//	"warn":  log.WarnLevel,
	//	"error": log.ErrorLevel,
	//}
	//logFormats = map[string]log.Formatter{
	//	"text": &log.TextFormatter{},
	//	"json": &log.JSONFormatter{},
	//}
)
var version string

//go:embed templates/*
var templates embed.FS

//go:embed frontend/static
var content embed.FS

type OvpnAdmin struct {
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	serverConf             openvpn.OvpnConfig
	clients                []*model.Device
	triggerUpdateChan      chan *model.Device
	promRegistry           *prometheus.Registry
	//mgmtInterface          string
	createUserMutex        *sync.Mutex
	updatedUsers           []*model.Device
	applicationPreferences model.ApplicationConfig
	wsConnections          []*rpi.WsSafeConn
	outboundIp             net.IP
	mgmt                   mgmt.OpenVPNmgmt
}

type MessagePayload struct {
	Message string `json:"message"`
}

func enableCors(w *http.ResponseWriter, r *http.Request) bool {
	// TODO: manage whitelist of origins
	isCors := (*r).Method == "OPTIONS" || len((*r).Header.Get("Origin")) > 0
	if isCors {
		(*w).Header().Set("Access-Control-Allow-Origin", (*r).Header.Get("Origin"))
		(*w).Header().Set("Access-Control-Allow-Credentials", "true")
		(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	}
	if (*r).Method == "OPTIONS" {
		return true
	}
	return false
}

func returnErrorMessage(w http.ResponseWriter, status int, err error) {
	jsonRaw, _ := json.Marshal(MessagePayload{Message: err.Error()})
	http.Error(w, string(jsonRaw), status)
}

func returnJson(w http.ResponseWriter, v any) error {
	jsonRaw, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(jsonRaw)
	return err
}

func returnText(w http.ResponseWriter, v string) error {
	w.Header().Set("Content-Type", "application/text")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(v))
	return err
}

var app OvpnAdmin

func main() {
	rand.Seed(time.Now().UnixNano())
	kingpin.Version(version)
	kingpin.Parse()

	//log.Printf("PATH %s\n", os.Getenv("PATH"))

	oAdmin := new(OvpnAdmin)
	oAdmin.lastSyncTime = "unknown"
	oAdmin.lastSuccessfulSyncTime = "unknown"
	oAdmin.masterSyncToken = *masterSyncToken
	oAdmin.promRegistry = prometheus.NewRegistry()
	oAdmin.createUserMutex = &sync.Mutex{}
	//oAdmin.mgmtInterface = *mgmtAddress
	oAdmin.outboundIp = shell.GetOutboundIP()
	oAdmin.clients = make([]*model.Device, 0)

	oAdmin.mgmt.GetConnection = oAdmin.getConnection
	oAdmin.mgmt.GetUserConnection = oAdmin.getUserConnection
	oAdmin.mgmt.TriggerBroadcastUser = oAdmin.triggerBroadcastUser
	oAdmin.mgmt.SynchroConnections = oAdmin.synchroConnections
	oAdmin.mgmt.AddClientConnection = oAdmin.addClientConnection
	oAdmin.mgmt.BroadcastWritePacket = func(line string) {
		oAdmin.broadcast(WebsocketPacket{Stream: "write", Data: line})
	}
	oAdmin.mgmt.BroadcastReadPacket = func(line string) {
		oAdmin.broadcast(WebsocketPacket{Stream: "read", Data: line})
	}

	openvpn.ParseServerConf(&oAdmin.serverConf, *serverConfFile)
	//log.Printf("loaded config %v", oAdmin.serverConf)

	preference.LoadPreferences(
		&oAdmin.applicationPreferences,
		*ovpnConfigDir,
		*jwtSecretFile,
	)

	oAdmin.registerMetrics()

	if len(oAdmin.serverConf.Management) > 0 {
		go oAdmin.connectToManagementInterface()
	}

	upgrader.CheckOrigin = oAdmin.checkWebsocketOrigin
	upgrader.Subprotocols = []string{"ovpn"}
	// initial device load
	for _, cert := range openvpn.IndexTxtParserCertificate(*easyrsaDirPath + "/pki") {
		if cert.Username != oAdmin.serverConf.MasterCn {
			oAdmin.createOrUpdateDeviceByCertificate(cert)
		}
	}
	oAdmin.triggerUpdateChan = make(chan *model.Device)
	go oAdmin.autoUpdate()

	staticDir, _ := fs.Sub(content, "frontend/static")
	embedFs := http.FS(staticDir)
	http.HandleFunc("/api/ws", oAdmin.handleWebsocketCommand)
	http.HandleFunc("/api/authenticate", oAdmin.authenticate)
	http.HandleFunc("/api/logout", oAdmin.logout)
	http.HandleFunc("/api/config", oAdmin.handleConfigCommand)
	http.HandleFunc("/api/config/", oAdmin.handleConfigCommand)
	http.HandleFunc("/api/openvpn", oAdmin.handleOpenvpnCommand)
	http.HandleFunc("/api/openvpn/", oAdmin.handleOpenvpnCommand)
	//http.HandleFunc("/api/config/preferences/save", oAdmin.postPreferences)
	//http.HandleFunc("/api/config/admin/", oAdmin.handleAdminAccount)
	//http.HandleFunc("/api/config/api-key/", oAdmin.handleApiKey)
	http.HandleFunc("/api/user", oAdmin.handleUserCommand)
	http.HandleFunc("/api/user/", oAdmin.handleUserCommand)
	http.HandleFunc("/api/node", oAdmin.handleNodeCommand)
	http.HandleFunc("/api/node/", oAdmin.handleNodeCommand)

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

func getBasicAuth(r *http.Request) string {
	username, password, ok := r.BasicAuth()
	if ok && username == "api" {
		return password
	}
	return ""
}

func (app *OvpnAdmin) triggerBroadcastUser(user *model.Device) {
	if user == nil {
		return
	}
	for _, u := range app.updatedUsers {
		if u == user {
			return
		}
	}
	app.updatedUsers = append(app.updatedUsers, user)
}

func apiKeyMapper(apiKey model.ApiKey) model.ConfigPublicApiKey {
	return model.ConfigPublicApiKey{Id: apiKey.Id.String(), Comment: apiKey.Comment, Expires: apiKey.Expires.Format(time.RFC3339)}
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

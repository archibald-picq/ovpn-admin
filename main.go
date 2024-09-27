package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"os"
	"rpiadm/backend/mgmt"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/preference"
	"rpiadm/backend/rpi"
	"rpiadm/backend/shell"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"

	"github.com/alecthomas/kingpin/v2"
)

const (
	stringDateFormat = "2006-01-02 15:04:05"
)

var (
	serverConfFile  = kingpin.Flag("server.conf", "Configuration file for the server").Default("/etc/openvpn/server.conf").Envar("OPENVPN_SERVER_CONF").String()
	listenHost      = kingpin.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort      = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8042").Envar("OVPN_LISTEN_PORT").String()
	masterSyncToken = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	//openvpnNetwork       = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("").Envar("OVPN_NETWORK").String()
	openvpnServer  = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	metricsPath    = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaBinPath = kingpin.Flag("easyrsa.bin", "path to easyrsa dir").Default("/usr/share/easy-rsa/easyrsa").Envar("EASYRSA_BIN").String()
	easyrsaDirPath = kingpin.Flag("easyrsa.path", "path to easyrsa config").Default("/etc/openvpn/easyrsa").Envar("EASYRSA_DIR").String()
	//ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	ovpnConfigDir            = kingpin.Flag("config.dir", "Configuration files dir").Default("/etc/openvpn/admin").Envar("CONFIG_DIR").String()

	upgrader = websocket.Upgrader{} // use default options
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
	serverConf             *openvpn.OvpnConfig
	clients                []*model.Device
	triggerUpdateChan      chan *model.Device
	promRegistry           *prometheus.Registry
	createUserMutex        *sync.Mutex
	updatedUsers           []*model.Device
	applicationPreferences model.ApplicationConfig
	wsConnections          []*rpi.WsSafeConn
	outboundIp             net.IP
	mgmt                   mgmt.OpenVPNmgmt
	easyrsa                openvpn.Easyrsa
}

type MessagePayload struct {
	Message string `json:"message"`
}

var app OvpnAdmin

func main() {
	rand.Seed(time.Now().UnixNano())
	kingpin.Version(version)
	kingpin.Parse()

	//log.Printf("PATH %s\n", os.Getenv("PATH"))

	app := new(OvpnAdmin)
	app.lastSyncTime = "unknown"
	app.lastSuccessfulSyncTime = "unknown"
	app.masterSyncToken = *masterSyncToken
	app.promRegistry = prometheus.NewRegistry()
	app.createUserMutex = &sync.Mutex{}
	//app.mgmtInterface = *mgmtAddress
	app.outboundIp = shell.GetOutboundIP()
	app.clients = make([]*model.Device, 0)

	app.mgmt.GetConnection = app.getConnection
	app.mgmt.GetUserConnection = app.getUserConnection
	app.mgmt.TriggerBroadcastUser = app.triggerBroadcastUser
	app.mgmt.SynchroConnections = app.synchroConnections
	app.mgmt.AddClientConnection = app.addClientConnection
	app.mgmt.BroadcastWritePacket = func(line string) {
		app.broadcast(WebsocketPacket{Stream: "write", Data: line})
	}
	app.mgmt.BroadcastReadPacket = func(line string) {
		app.broadcast(WebsocketPacket{Stream: "read", Data: line})
	}

	preference.LoadPreferences(
		&app.applicationPreferences,
		*ovpnConfigDir,
	)
	log.Printf("  -> users: %d", len(app.applicationPreferences.Users))
	log.Printf("  -> api keys: %d", len(app.applicationPreferences.ApiKeys))
	log.Printf("  -> server host: %s", app.applicationPreferences.Preferences.Address)

	path, err := os.Getwd()
	if err != nil {
		log.Fatal("Can't get CWD")
	}

	log.Printf("current working directory %s", path)
	//log.Printf("  -> absolutize ccd '%s' + '%s'", path, *serverConfFile)
	*serverConfFile = shell.AbsolutizePath(path+"/", *serverConfFile)
	//log.Printf("Reading openvpn server config '%s'", *serverConfFile)
	app.serverConf = openvpn.ParseServerConf(*serverConfFile)
	if app.serverConf != nil {
		log.Printf("  -> network: %s", app.serverConf.Server)
		log.Printf("  -> master certificate: %s", app.serverConf.MasterCn)
		log.Printf("  -> management address: %s", app.serverConf.Management)

		//*serverConfFile = shell.AbsolutizePath(*serverConfFile, app.serverConf.ClientConfigDir)
		//log.Printf("  -> absolutize ccd '%s' + '%s'", *serverConfFile, app.serverConf.ClientConfigDir)
		log.Printf("  -> ccd dir: '%s'", shell.AbsolutizePath(*serverConfFile, app.serverConf.ClientConfigDir))
	}

	log.Printf("Reading easyrsa certificates")
	app.easyrsa.EasyrsaBinPath = shell.AbsolutizePath(path+"/", *easyrsaBinPath)
	app.easyrsa.EasyrsaDirPath = shell.AbsolutizePath(path+"/", *easyrsaDirPath)
	log.Printf("  -> easyrsa bin: '%s' (%s)", app.easyrsa.EasyrsaBinPath, openvpn.CheckEasyrsaVersionOrAbsent(app.easyrsa))
	if openvpn.IndexTxtExists(app.easyrsa) {
		log.Printf("  -> pki dir: '%s' (exists)", app.easyrsa.EasyrsaDirPath+"/pki/index.txt")
		//log.Printf("loaded config %v", app.serverConf)
		// initial device load
		for _, cert := range openvpn.IndexTxtParserCertificate(app.easyrsa) {
			app.createOrUpdateDeviceByCertificate(cert)
		}
		log.Printf("  -> certificates: %d (ccd: %d)", len(app.clients), app.countClientsWithCcd())
	} else if openvpn.IsPkiInited(app.easyrsa) {
		log.Printf("  -> pki dir: '%s' (initializing)", app.easyrsa.EasyrsaDirPath+"/pki")
	} else {
		log.Printf("  -> pki dir: '%s' (absent)", app.easyrsa.EasyrsaDirPath+"/pki")
	}
	app.registerMetrics()

	if app.serverConf != nil && len(app.serverConf.Management) > 0 {
		go app.connectToManagementInterface()
	}

	upgrader.CheckOrigin = app.checkWebsocketOrigin
	upgrader.Subprotocols = []string{"ovpn"}
	app.triggerUpdateChan = make(chan *model.Device)
	go app.autoUpdate()

	staticDir, _ := fs.Sub(content, "frontend/static")
	embedFs := http.FS(staticDir)
	http.HandleFunc("/api/ws", app.handleWebsocketCommand)
	http.HandleFunc("/api/authenticate", app.authenticate)
	http.HandleFunc("/api/logout", app.logout)
	http.HandleFunc("/api/config", app.handleConfigCommand)
	http.HandleFunc("/api/config/", app.handleConfigCommand)
	http.HandleFunc("/api/openvpn", app.handleOpenvpnCommand)
	http.HandleFunc("/api/openvpn/", app.handleOpenvpnCommand)
	//http.HandleFunc("/api/config/preferences/save", app.postPreferences)
	//http.HandleFunc("/api/config/admin/", app.handleAdminAccount)
	//http.HandleFunc("/api/config/api-key/", app.handleApiKey)
	http.HandleFunc("/api/user", app.handleUserCommand)
	http.HandleFunc("/api/user/", app.handleUserCommand)
	http.HandleFunc("/api/node", app.handleNodeCommand)
	http.HandleFunc("/api/node/", app.handleNodeCommand)

	http.Handle(*metricsPath, promhttp.HandlerFor(app.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		app.catchAll(embedFs, w, r)
	})

	log.Printf("Admin interface: http://%s:%s", *listenHost, *listenPort)
	log.Fatal(http.ListenAndServe(*listenHost+":"+*listenPort, nil))
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

func (app *OvpnAdmin) countClientsWithCcd() int {
	count := 0
	for _, c := range app.clients {
		if c.Ccd != nil {
			count++
		}
	}
	return count
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

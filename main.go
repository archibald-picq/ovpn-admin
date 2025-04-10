package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"os"
	"rpiadm/backend/ble"
	"rpiadm/backend/cli"
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
	pin     = kingpin.New("rpiadm", "System management agent")
	cliMode = pin.Command("cli", "Connect to the local daemon").Default()

	cliCommand = cliMode.Arg("cmd", "Command to send").String()

	daemonMode = pin.Command("daemon", "Start the daemon agent")
	clientMode = pin.Command("connect", "Connect to the daemon remotely")

	remoteAddress = clientMode.Arg("address:port", "Remote address to connect").Default("localhost:8042").String()

	serverConfFil   = daemonMode.Flag("server.conf", "Configuration file for the server").Default("/etc/openvpn/server.conf").Envar("OPENVPN_SERVER_CONF").String()
	listenHost      = daemonMode.Flag("listen.host", "host for ovpn-admin").Default("0.0.0.0").Envar("OVPN_LISTEN_HOST").String()
	listenPort      = daemonMode.Flag("listen.port", "port for ovpn-admin").Default("8042").Envar("OVPN_LISTEN_PORT").String()
	masterSyncToken = daemonMode.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	//openvpnNetwork       = kingpin.Flag("ovpn.network", "NETWORK/MASK_PREFIX for OpenVPN server").Default("").Envar("OVPN_NETWORK").String()
	openvpnServer  = daemonMode.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server; can have multiple values").Default("").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	metricsPath    = daemonMode.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaBinPath = daemonMode.Flag("easyrsa.bin", "path to easyrsa dir").Default("/usr/share/easy-rsa/easyrsa").Envar("EASYRSA_BIN").String()
	easyrsaDirPath = daemonMode.Flag("easyrsa.path", "path to easyrsa config").Default("/etc/openvpn/easyrsa").Envar("EASYRSA_DIR").String()
	//ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	authByPassword = daemonMode.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase   = daemonMode.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	ovpnConfigDir  = daemonMode.Flag("config.dir", "Configuration files dir").Default("/etc/openvpn/admin").Envar("CONFIG_DIR").String()
)
var version string

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
	applicationPreferences preference.ApplicationConfig
	wsConnections          []*rpi.WsSafeConn
	outboundIp             net.IP
	mgmt                   mgmt.OpenVPNmgmt
	easyrsa                openvpn.Easyrsa
	bleConfig              *ble.BleConfig
}

type MessagePayload struct {
	Message string `json:"message"`
}

var app OvpnAdmin

func main() {
	rand.Seed(time.Now().UnixNano())
	kingpin.Version(version)
	//kingpin.Parse()
	//switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	//log.Printf("command: %v\n", command)

	switch kingpin.MustParse(pin.Parse(os.Args[1:])) {
	case daemonMode.FullCommand():
		app.startDaemonMode()
	case clientMode.FullCommand():
		log.Printf("connect to: %s", *remoteAddress)
	case cliMode.FullCommand():
		log.Printf("running command: %s", cliMode.FullCommand())
		cli.ConnectEchoSocket(cliCommand)
	default:
		cli.ConnectEchoSocket(nil)
	}
}

func (app *OvpnAdmin) startDaemonMode() {

	//app.bleConfig = new(ble.BleConfig)
	//app.bleConfig.AdvertiseBlePeripheral(app.runCommand)

	log.Println("BindEchoSocket")
	go cli.BindEchoSocket()
	log.Println("done BindEchoSocket")

	daemon()
}

func (app *OvpnAdmin) runCommand(cmd string, data json.RawMessage) (interface{}, error) {
	return nil, errors.New("unknown command \"" + cmd + "\"")
}

func daemon() {
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

	app.applicationPreferences.LoadPreferences(*ovpnConfigDir)
	log.Printf("  -> users: %d", len(app.applicationPreferences.Users))
	log.Printf("  -> api keys: %d", len(app.applicationPreferences.ApiKeys))
	log.Printf("  -> server host: %s", app.applicationPreferences.Preferences.Address)
	log.Printf("  -> jwt private key set with %d bytes", len(app.applicationPreferences.JwtData))

	path, err := os.Getwd()
	if err != nil {
		log.Fatal("Can't get CWD")
	}

	//log.Printf("current working directory %s", path)

	app.serverConf = openvpn.ParseServerConf(shell.AbsolutizePath(path+"/", *serverConfFil))

	app.easyrsa.EasyrsaBinPath = shell.AbsolutizePath(path+"/", *easyrsaBinPath)
	app.easyrsa.EasyrsaDirPath = shell.AbsolutizePath(path+"/", *easyrsaDirPath)
	log.Printf("Reading easyrsa pki at '%s'", app.easyrsa.EasyrsaDirPath+"/pki")
	log.Printf("  -> easyrsa bin: '%s' (%s)", app.easyrsa.EasyrsaBinPath, app.easyrsa.CheckEasyrsaVersionOrAbsent())
	if app.easyrsa.IndexTxtExists() {
		log.Printf("  -> pki index: '%s' (exists)", app.easyrsa.EasyrsaDirPath+"/pki/index.txt")
		//log.Printf("loaded config %v", app.serverConf)
		// initial device load
		allCerts := app.easyrsa.IndexTxtParserCertificate()
		//log.Printf("  -> index.txt: %d entry loaded", len(allCerts))
		allCerts = app.easyrsa.PatchRevokedCertificates(allCerts)
		log.Printf("  -> index.txt: %d entry loaded", len(allCerts))
		for _, cert := range allCerts {
			if len(cert.Username) > 0 && cert.Flag != "D" {
				app.createOrUpdateDeviceByCertificate(cert)
			}
		}
		log.Printf("  -> active certificates: %d (ccd: %d)", len(app.clients), app.countClientsWithCcd())
	} else if app.easyrsa.IsPkiInited() {
		log.Printf("  -> pki dir: '%s' (initializing)", app.easyrsa.EasyrsaDirPath+"/pki")
	} else {
		log.Printf("  -> pki dir: '%s' (absent)", app.easyrsa.EasyrsaDirPath+"/pki")
	}

	app.registerMetrics()
	if app.serverConf != nil {
		if len(app.serverConf.CrlVerify) > 0 {
			app.easyrsa.UpdateCertificateRevocationList(app.serverConf.GetCrlPath())
		} else {
			log.Printf("  -> crl is not enabled !!!")
		}

		if len(app.serverConf.Management) > 0 {
			go app.connectToManagementInterface()
		}
	}

	app.triggerUpdateChan = make(chan *model.Device)
	go app.autoUpdate()

	app.restapi()
	app.webapp()

	log.Printf("Admin interface: http://%s:%s", *listenHost, *listenPort)
	log.Fatal(http.ListenAndServe(*listenHost+":"+*listenPort, nil))
}

func (app *OvpnAdmin) restapi() {
	// maybe separate websocket ?
	upgrader.CheckOrigin = app.checkWebsocketOrigin
	upgrader.Subprotocols = []string{"ovpn"}
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

	// health & monitoring
	http.Handle(*metricsPath, promhttp.HandlerFor(app.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong")
	})
}

func (app *OvpnAdmin) webapp() {
	staticDir, _ := fs.Sub(content, "frontend/static")
	embedFs := http.FS(staticDir)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		app.catchAll(embedFs, w, r)
	})
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

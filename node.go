package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
)

type Repository struct {
	Type     string  `json:"type"`  // deb | deb-src
	SignedBy *string `json:"signedBy,omitempty"`
	Arch     *string `json:"arch,omitempty"`
	Url      string  `json:"url"`
	Tag      string  `json:"tag"`
	Branch   string  `json:"branch"`
}

type AptSource struct {
	Name  string       `json:"name"`
	Repos []Repository `json:"repos"`
}

type Package struct {
	Name    string    `json:"name"`
	Version string    `json:"version"` // latest | 1.42.0 | ^1.0.0 | ~1.41.0 | 1.41.99-demo
}

type CustomFile struct {
	Type       string  `json:"type"` // file | dir
	Mode       int     `json:"mode"`
	TargetPath string  `json:"path"`
	SourceType string  `json:"sourceType"` // local | url | embed
	Content    *string `json:"content"`
	DiffMode   bool    `json:"diffMode"` // replace | append | diff
}

type NetInterfaceConfig interface {

}

type NetWifiClientConfig struct {
	Ssid	string `json:"ssid"`
	Key     string `json:"key"`

	NetInterfaceConfig
}

type NetSoracomClientConfig struct {
	Username  string `json:"username"`
	Password  string `json:"password"`

	NetInterfaceConfig
}


type NetInterface struct {
	Dev      string   `json:"dev"` // eth0 | wlan0 | br0 | bond0
	Mode     string   `json:"mode"` // dhcp-client | dhcp-server | static
	Addr     string   `json:"addr"` // 192.168.66.45/24
	Bridge   []string `json:"bridge"` // ['eth0', 'wlan0'] | ['
	Config   NetInterfaceConfig `json:"config"`
}

type InstallProfile struct {
	ParentRaw    string `json:"parent"`
	Parent       *InstallProfile `json:"-"`
	Packages     []Package       `json:"packages"`
	Repositories []AptSource     `json:"repositories"`
	CustomFiles  []CustomFile    `json:"customFiles"`
	Interfaces   []NetInterface  `json:"interfaces"`
}

type NodeConfig struct {
	Hostname    string          `json:"hostname"` // bluebox, whitebox, pi
	AutoUpdate  bool            `json:"autoUpdate"` // also auto-install
	Profile     *InstallProfile `json:"profile,omitempty"`
}

func (packet *InstallProfile) UnmarshalJSON(data []byte) error {
	log.Printf("unserialize %s", string(data))
	return nil
}

func (app *OvpnAdmin) handleReadNodeConfig(w http.ResponseWriter, r *http.Request) {
	//log.Debug(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	re := regexp.MustCompile("^/api/node/(.*)$")
	matches := re.FindStringSubmatch(r.URL.Path)
	log.Printf("get config for node %s (%v)", r.URL.Path, matches)
	if len(matches) > 0 {
		payload, err := app.readNodeConfig(matches[1])
		if err != nil {
			jsonRaw, _ := json.Marshal(MessagePayload{Message: fmt.Sprintf("Failed read config for user %s: %¨s", matches[1], err)})
			http.Error(w, string(jsonRaw), http.StatusBadRequest)
			return
		}
		rawJson, _ := json.Marshal(payload)
		//w.WriteHeader(http.StatusOK)
		w.Write(rawJson)
		return
	} else {
		jsonRaw, _ := json.Marshal(MessagePayload{Message: "Bad request"})
		http.Error(w, string(jsonRaw), http.StatusBadRequest)
		return
	}

}

func (app *OvpnAdmin) readNodeConfig(certName string) (NodeConfig, error) {
	p := *ovpnConfigDir + "/nodes/"+certName+".json"
	if _, err := os.Stat(p); err != nil {
		log.Printf("config file %s does not exists", p)
		return NodeConfig{}, nil
	}

	rawFile, err := os.ReadFile(p)
	if err != nil {
		log.Printf("can't read file %s", p)
		return NodeConfig{}, nil
	}

	var nodeConfig NodeConfig
	err = json.Unmarshal(rawFile, &nodeConfig)
	if err != nil {
		log.Printf("Can't decode config for %s", certName)
		return NodeConfig{}, nil
	}
	log.Printf("decoded %v", nodeConfig)



	// wget -qO- https://repos.influxdata.com/influxdb.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/influxdb.gpg > /dev/null
	//export DISTRIB_ID=$(lsb_release -si); export DISTRIB_CODENAME=$(lsb_release -sc)
	//echo "deb [signed-by=/etc/apt/trusted.gpg.d/influxdb.gpg] https://repos.influxdata.com/${DISTRIB_ID,,} ${DISTRIB_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/influxdb.list > /dev/null


	return nodeConfig, nil
}

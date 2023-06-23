package rpi

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type LsbInfo struct {
	PrettyName      string `json:"prettyName"`
	Name            string `json:"name"`
	VersionId       int    `json:"versionId"`
	Version         string `json:"version"`
	VersionCodename string `json:"versionCodename"`
	Id              string `json:"id"`
	IdLike          string `json:"idLike"`
	HomeUrl         string `json:"homeUrl"`
	SupportUrl      string `json:"supportUrl"`
	BugReportUrl    string `json:"bugReportUrl"`
}

type Dpkg struct {
	Version  string             `json:"version"`
	Lsb      *LsbInfo           `json:"lsb,omitempty"`
	Packages []InstalledPackage `json:"packages"`
}

type InstalledPackage struct {
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	Arch         string  `json:"arch"`
	Description  string  `json:"description"`
	DesiredState string  `json:"desiredState"`
	State        string  `json:"state"`
	Error        *string `json:"error,omitempty"`
}

type RpiState struct {
	Lsb                        *LsbInfo `json:"lsb,omitempty"`
	InstalledPackages          []InstalledPackage
	InstalledPackagesLastCheck time.Time
}

func ReadNodeConfig(ovpnConfigDir string, certName string) (NodeConfig, error) {
	p := ovpnConfigDir + "/nodes/" + certName + ".json"
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

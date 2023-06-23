package rpi

import "log"

type Repository struct {
	Type     string  `json:"type"` // deb | deb-src
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
	Name    string `json:"name"`
	Version string `json:"version"` // latest | 1.42.0 | ^1.0.0 | ~1.41.0 | 1.41.99-demo
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
	Ssid string `json:"ssid"`
	Key  string `json:"key"`

	NetInterfaceConfig
}

type NetSoracomClientConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`

	NetInterfaceConfig
}

type NetInterface struct {
	Dev    string             `json:"dev"`    // eth0 | wlan0 | br0 | bond0
	Mode   string             `json:"mode"`   // dhcp-client | dhcp-server | static
	Addr   string             `json:"addr"`   // 192.168.66.45/24
	Bridge []string           `json:"bridge"` // ['eth0', 'wlan0'] | ['
	Config NetInterfaceConfig `json:"config"`
}

type InstallProfile struct {
	ParentRaw    string          `json:"parent"`
	Parent       *InstallProfile `json:"-"`
	Packages     []Package       `json:"packages"`
	Repositories []AptSource     `json:"repositories"`
	CustomFiles  []CustomFile    `json:"customFiles"`
	Interfaces   []NetInterface  `json:"interfaces"`
}

func (packet *InstallProfile) UnmarshalJSON(data []byte) error {
	log.Printf("unserialize %s", string(data))
	return nil
}

type NodeConfig struct {
	Hostname   string          `json:"hostname"`   // bluebox, whitebox, pi
	AutoUpdate bool            `json:"autoUpdate"` // also auto-install
	Profile    *InstallProfile `json:"profile,omitempty"`
}

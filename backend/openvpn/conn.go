package openvpn

import "time"

type Network struct {
	Address  string `json:"address"`
	Netmask  string `json:"netmask"`
	LastSeen string `json:"lastSeen"`
}

type NodeInfo struct {
	Address  string `json:"address"`
	LastSeen string `json:"lastSeen"`
}

type VpnClientConnection struct {
	ClientId           int64 `json:"clientId"`
	CommonName         string
	RealAddress        string     `json:"realAddress"`
	BytesReceived      int64      `json:"bytesReceived"`
	BytesSent          int64      `json:"bytesSent"`
	SpeedBytesReceived int64      `json:"speedBytesReceived"`
	SpeedBytesSent     int64      `json:"speedBytesSent"`
	LastByteReceived   time.Time  `json:"-"`
	ConnectedSince     *string    `json:"connectedSince"`
	VirtualAddress     *string    `json:"virtualAddress"`
	VirtualAddressIPv6 *string    `json:"virtualAddressIPv6"`
	LastRef            *string    `json:"lastRef"`
	Nodes              []NodeInfo `json:"nodes"`
	Networks           []Network  `json:"networks"`
}

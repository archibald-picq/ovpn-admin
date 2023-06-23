package model

import (
	"rpiadm/backend/openvpn"
	"rpiadm/backend/rpi"
)

type ClientCertificate struct {
	Username    string               `json:"username"`
	Certificate *openvpn.Certificate `json:"certificate"`

	ConnectionStatus string                         `json:"connectionStatus"`
	Connections      []*openvpn.VpnClientConnection `json:"connections"`
	Rpic             []*rpi.WsRpiConnection         `json:"rpic"`
	RpiState         *rpi.RpiState                  `json:"rpiState,omitempty"`
}

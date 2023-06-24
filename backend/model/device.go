package model

import (
	"rpiadm/backend/openvpn"
	"rpiadm/backend/rpi"
)

type Device struct {
	Username         string                   `json:"username"`
	ConnectionStatus string                   `json:"connectionStatus"`
	Certificate      *openvpn.Certificate     `json:"certificate"`
	RpiState         *rpi.RpiState            `json:"rpiState,omitempty"`
	Connections      []*openvpn.VpnConnection `json:"connections"`
	Rpic             []*rpi.RpiConnection     `json:"rpic"`
}

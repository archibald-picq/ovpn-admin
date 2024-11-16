package ble

import "rpiadm/backend/connection"

type BleConfig struct {
	bleConnection *connection.BleConnection
	bleConn       connection.Connection
}

package ble

import (
	"log"
	"rpiadm/backend/connection"
)

func (config *BleConfig) AdvertiseBlePeripheral(callback connection.CommandCallback) {

	config.bleConnection = new(connection.BleConnection)
	config.bleConn = connection.Connection{
		Name: "ble",
		Abs:  config.bleConnection,
		OnConnect: func() {
			log.Printf("Connected BLE central")
		},
		OnCommand: callback,
	}
	config.bleConnection.Base = &config.bleConn
	err := config.bleConnection.Connect()
	if err != nil {
		log.Printf("Can't start BLE: %v", err)
	}
}

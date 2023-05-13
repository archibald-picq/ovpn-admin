package main

import (
	"log"
	"time"
)

func (app *OvpnAdmin) addOrUpdateRpic(user *ClientCertificate, ws *WsSafeConn) {
	connection := new(WsRpiConnection)
	connection.ws = ws
	connection.ConnectedSince = time.Now()
	connection.LastRef = time.Now()
	connection.RealAddress = ws.ws.RemoteAddr().String()
	if len(connection.ws.xForwardedFor) > 0 {
		connection.RealAddress = connection.ws.xForwardedFor
	}
	if connection.ws.xForwardedProto == "https" {
		connection.Ssl = true
	}
	if len(connection.ws.userAgent) > 0 {
		connection.UserAgent = &connection.ws.userAgent
	}
	user.Rpic = append(user.Rpic, connection)
	log.Printf("rpi connected for %d\n", user.Username)
}

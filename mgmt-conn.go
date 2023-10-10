package main

import (
	"net"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
	"rpiadm/backend/rpi"
	"text/template"
	"time"

	"log"
)

func parseDate(layout, datetime string) time.Time {
	t, err := time.Parse(layout, datetime)
	if err != nil {
		log.Printf(err.Error())
		return time.Time{}
	}
	return t
}

func parseDateToUnix(layout, datetime string) int64 {
	return parseDate(layout, datetime).Unix()
}

func (app *OvpnAdmin) addClientConnection(client *openvpn.VpnConnection) {
	log.Printf("add %v", client)
	device := app.getDevice(client.CommonName)
	//isNew := true
	if device == nil {
		log.Printf("Can't find device for %s", client.CommonName)
		return
	}
	var found *openvpn.VpnConnection
	for _, conn := range device.Connections {
		if conn.ClientId == client.ClientId {
			found = conn
			//isNew = false
			break
		}
	}
	if found == nil {
		log.Printf("Push connection '%v'", client)
		//log.Printf("Can't find device for %s", client.CommonName)
		device.Connections = append(device.Connections, client)
		found = client
	}
	found.RealAddress = client.RealAddress
	found.ConnectedSince = client.ConnectedSince
	found.BytesSent = client.BytesSent
	found.BytesReceived = client.BytesReceived
	found.SpeedBytesSent = client.SpeedBytesSent
	found.SpeedBytesReceived = client.SpeedBytesReceived
	found.LastRef = client.LastRef
	found.VirtualAddress = client.VirtualAddress
	found.VirtualAddressIPv6 = client.VirtualAddressIPv6

	updatedUsers := []*model.Device{device}
	app.broadcast(WebsocketPacket{Stream: "user.update", Data: updatedUsers})
	//log.Warnf("updating single user %s", user.Username)
	app.broadcast(WebsocketPacket{Stream: "user.update." + device.Username, Data: updatedUsers[0]})
	app.broadcast(WebsocketPacket{Stream: "user.update." + device.Username + ".connections", Data: updatedUsers[0].Connections})
	//oAdmin.activeConnections = append(oAdmin.activeConnections, client)
}

func (app *OvpnAdmin) getUserConnection(user string, clientId int64) (*model.Device, *openvpn.VpnConnection) {
	for _, u := range app.clients {
		if u.Username == user {
			for _, c := range u.Connections {
				if c.ClientId == clientId {
					return u, c
				}
			}
		}
	}
	return nil, nil
}

func (app *OvpnAdmin) getConnection(clientId int64) (*model.Device, *openvpn.VpnConnection) {
	//log.Printf("search connection %d in %d clients", clientId, len(app.clients))
	for _, u := range app.clients {
		//log.Printf(" - client %s", u.Username)
		for _, c := range u.Connections {
			//log.Printf("   - conn %d", c.ClientId)
			if c.ClientId == clientId {
				return u, c
			}
		}
	}
	return nil, nil
}

func (app *OvpnAdmin) updateCertificateStats() {
	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()

	for _, line := range app.clients {
		if line.Username != app.masterCn && line.Certificate.Flag != "D" {
			totalCerts += 1
			switch {
			case line.Certificate.Flag == "V":
				validCerts += 1
			case line.Certificate.Flag == "R":
				revokedCerts += 1
			case line.Certificate.Flag == "E":
				expiredCerts += 1
			}

			ovpnClientCertificateExpire.WithLabelValues(line.Certificate.Identity).Set(float64((parseDateToUnix(stringDateFormat, line.Certificate.ExpirationDate) - apochNow) / 3600 / 24))

			app.updateDeviceByCertificate(line.Certificate)

		} else {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(stringDateFormat, line.Certificate.ExpirationDate) - apochNow) / 3600 / 24))
		}
	}

	//app.updateConnections()

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Printf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))
}

func (app *OvpnAdmin) updateDeviceByCertificate(certificate *openvpn.Certificate) {
	for idx, existing := range app.clients {
		if existing.Username == certificate.Username {
			app.clients[idx].Certificate = certificate
			app.clients[idx].Certificate.Flag = certificate.Flag
			app.clients[idx].Certificate.DeletionDate = certificate.DeletionDate
			log.Printf("update certificate", app.clients[idx].Certificate)
			return
		}
	}
	app.clients = append(app.clients, &model.Device{
		Username:         certificate.Username,
		ConnectionStatus: "",
		Certificate:      certificate,
		RpiState:         nil,
		Connections:      make([]*openvpn.VpnConnection, 0),
		Rpic:             make([]*rpi.RpiConnection, 0),
	})
}

func (app *OvpnAdmin) synchroConnections(conns []*openvpn.VpnConnection) {
	for _, client := range app.clients {
		client.Connections = make([]*openvpn.VpnConnection, 0)
	}
	for _, conn := range conns {
		var found = false
		for _, client := range app.clients {
			if client.Username == conn.CommonName {
				client.Connections = append(client.Connections, conn)
				found = true
			}
		}
		if !found {
			log.Printf("Can't find certificate for connection %s from %s", conn.CommonName, conn.RealAddress)
		}
	}
	app.broadcast(WebsocketPacket{Stream: "users", Data: app.clients})
}

func (app *OvpnAdmin) getDevice(username string) *model.Device {
	for _, device := range app.clients {
		if device.Username == username {
			return device
		}
	}
	return nil
}

func (app *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTpl, clientConfigTplErr := templates.ReadFile("templates/client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Printf("clientConfigTpl not found in templates box")
		}
		return template.Must(template.New("client-config").Parse(string(clientConfigTpl)))
	}
}

func (app *OvpnAdmin) connectToManagementInterface() {
	go func() {
		for {
			time.Sleep(time.Duration(28) * time.Second)
			app.mgmt.SendManagementCommand("status 3")
		}
	}()
	go func() {
		for {
			time.Sleep(time.Duration(2) * time.Second)
			if len(app.updatedUsers) > 0 {
				app.broadcast(WebsocketPacket{Stream: "user.update", Data: app.updatedUsers})
				for i := range app.updatedUsers {
					//log.Warnf("updating single user %s", app.updatedUsers[i].Username)
					app.broadcast(WebsocketPacket{Stream: "user.update." + app.updatedUsers[i].Username, Data: app.updatedUsers[i]})
					app.broadcast(WebsocketPacket{Stream: "user.update." + app.updatedUsers[i].Username + ".connections", Data: app.updatedUsers[i].Connections})
				}
				app.updatedUsers = make([]*model.Device, 0)
			}
		}
	}()
	for {
		if len(app.mgmtInterface) == 0 {
			time.Sleep(time.Duration(30) * time.Second)
			continue
		}
		conn, err := net.Dial("tcp", app.mgmtInterface)
		if err != nil {
			log.Printf("openvpn mgmt interface is not reachable at %s", app.mgmtInterface)
			time.Sleep(time.Duration(30) * time.Second)
			continue
		}
		app.mgmt.Conn = conn
		go func() {
			app.mgmt.SendManagementCommand("version")
			app.mgmt.SendManagementCommand("status 3")
			resp := app.mgmt.SendManagementCommandWaitResponse("bytecount 5")
			log.Printf("register bytecount 5 returns: %s", resp)
		}()

		app.mgmt.HandleMessages()
	}

}

func (app *OvpnAdmin) killAndRemoveConnection(client *model.Device, conn *openvpn.VpnConnection) error {
	if err := app.mgmt.KillConnection(conn); err != nil {
		return err
	}
	for _, c := range app.clients {
		for j, co := range c.Connections {
			if co == conn {
				log.Printf("removed active connection %d", c)
				c.Connections = append(c.Connections[0:j], c.Connections[j+1:]...)
				//app.updateConnections(app.activeConnections)
				app.triggerBroadcastUser(client)
				break
			}
		}
	}

	return nil
}

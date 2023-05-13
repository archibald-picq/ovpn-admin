package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	log "github.com/sirupsen/logrus"
)
func (app *OvpnAdmin) getUserConnection(user string, clientId int64) *VpnClientConnection {
	for _, u := range app.clients {
		if u.Username == user {
			for _, c := range u.Connections {
				if c.ClientId == clientId {
					return c
				}
			}
		}
	}
	return nil
}
func (app *OvpnAdmin) mgmtConnectedUsersParser3(lines []string) []*VpnClientConnection {
	var u = make([]*VpnClientConnection, 0)
	//isClientList := false
	//isRouteTable := false
	for _, txt := range lines {
		if regexp.MustCompile(`^CLIENT_LIST\t`).MatchString(txt) {
			user := strings.Split(txt, "\t")

			bytesReceive, _ := strconv.ParseInt(user[5], 10, 64)
			bytesSent, _ := strconv.ParseInt(user[6], 10, 64)
			clientId, _ := strconv.ParseInt(user[10], 10, 64)
			//log.Infof("parsed client %s id %d from", user[1], clientId, user[10])
			var clientStatus = app.getUserConnection(user[1], clientId)
			if clientStatus == nil {
				clientStatus = new(VpnClientConnection)
			}
			clientStatus.ClientId = clientId
			clientStatus.commonName = user[1]
			clientStatus.RealAddress = user[2]
			clientStatus.BytesReceived = bytesReceive
			clientStatus.BytesSent = bytesSent
			clientStatus.lastByteReceived = time.Now()
			clientStatus.ConnectedSince = &user[7]
			clientStatus.VirtualAddress = &user[3]
			if user[4] != "" {
				clientStatus.VirtualAddressIPv6 = &user[4]
			}

			u = append(u, clientStatus)
		}
		if regexp.MustCompile(`^ROUTING_TABLE\t`).MatchString(txt) {
			user := strings.Split(txt, "\t")
			peerAddress := user[1]
			userName := user[2]
			realAddress := user[3]
			userConnectedSince := user[4]

			for i := range u {
				if u[i].commonName == userName && u[i].RealAddress == realAddress {
					if strings.HasSuffix(peerAddress, "C") {
						app.addOrUpdateNode(u[i], peerAddress[:len(peerAddress)-1], userConnectedSince)
					} else if strings.Contains(peerAddress, "/") {
						app.addOrUpdateNetwork(u[i], peerAddress, userConnectedSince)
					} else {
						//u[i].VirtualAddress = peerAddress
						u[i].LastRef = &userConnectedSince
					}
					//ovpnClientConnectionInfo.WithLabelValues(user[1], user[0]).Set(float64(parseDateToUnix(app.mgmtStatusTimeFormat, user[3])))
					break
				}
			}
		}
	}
	return u
}

func (app *OvpnAdmin) addOrUpdateNode(clientStatus *VpnClientConnection, peerAddress string, lastSeen string) {
	for i := range clientStatus.Nodes {
		if clientStatus.Nodes[i].Address == peerAddress {
			clientStatus.Nodes[i].LastSeen = lastSeen
			return
		}
	}
	clientStatus.Nodes = append(clientStatus.Nodes, NodeInfo{
		Address: peerAddress,
		LastSeen: lastSeen,
	})
}

func (app *OvpnAdmin) addOrUpdateNetwork(clientStatus *VpnClientConnection, peerAddress string, lastSeen string) {
	for i := range clientStatus.Networks {
		if clientStatus.Networks[i].Address == peerAddress {
			clientStatus.Networks[i].LastSeen = lastSeen
			return
		}
	}
	clientStatus.Networks = append(clientStatus.Networks, Network{
		Address: peerAddress,
		LastSeen: lastSeen,
	})
}

func (app *OvpnAdmin) killUserConnections(serverName *ClientCertificate) {
	app.sendManagementCommand(fmt.Sprintf("kill %s\n", serverName.Username))
}

func (app *OvpnAdmin) killConnection(serverName *VpnClientConnection) error {
	resp := app.sendManagementCommandWaitResponse(fmt.Sprintf("kill %s\n", serverName.RealAddress)) // address:port
	if resp.error {
		return errors.New(resp.body)
	}
	return nil
}

func (app *OvpnAdmin) connectToManagementInterface() {
	go func() {
		for {
			time.Sleep(time.Duration(28) * time.Second)
			app.sendManagementCommand("status 3")
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
				}
				app.updatedUsers = make([]*ClientCertificate, 0)
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
			log.Warnf("openvpn mgmt interface is not reachable at %s", app.mgmtInterface)
			time.Sleep(time.Duration(30) * time.Second)
			continue
		}
		app.conn = conn
		go func() {
			app.sendManagementCommand("version")
			app.sendManagementCommand("status 3")
			resp := app.sendManagementCommandWaitResponse("bytecount 5")
			log.Infof("register bytecount 5 returns: %s", resp)
		}()

		//app.sendManagementCommand("client-auth")

		scanner := bufio.NewScanner(app.conn)

		for scanner.Scan() {
			line := scanner.Text()

			// append to buffer and handle lines if recognized
			app.mgmtBuffer = append(app.mgmtBuffer, line)
			//log.Printf("live '%s'", line)
			app.broadcast(WebsocketPacket{Stream: "read", Data: line})
			for app.processMgmtBuffer() > 0 {

			}
			//ovpnClientBytesSent.Reset()
			//ovpnClientBytesReceived.Reset()
			//ovpnClientConnectionFrom.Reset()
			//ovpnClientConnectionInfo.Reset()
			//ovpnClientCertificateExpire.Reset()
		}
		log.Infof("end of scan")
	}

}

var regCommand = regexp.MustCompile("^>([A-Z_]+):")
var regStatus3 = regexp.MustCompile("^TITLE\tOpenVPN\\s+[0-9]+\\.[0-9]+\\.[0-9]+\\s+")
var regError = regexp.MustCompile("^ERROR:\\s+(.*)")
var regSuccess = regexp.MustCompile("^SUCCESS:\\s+(.*)")

func (app *OvpnAdmin) processMgmtBuffer() int {
	if len(app.mgmtBuffer) == 0 {
		return 0
	}
	firstWord := strings.TrimPrefix(strings.SplitN(app.mgmtBuffer[0], ":", 2)[0], ">")
	lastLine := app.mgmtBuffer[len(app.mgmtBuffer)-1]

	if firstWord == "BYTECOUNT_CLI" {
		app.handleBytecountUpdate(app.mgmtBuffer[0])
		app.mgmtBuffer = app.mgmtBuffer[1:]
		return 1
	}

	if firstWord == "ERROR" || firstWord == "SUCCESS" {
		if len(app.waitingCommands) > 0 {
			command := app.waitingCommands[0]
			//log.Printf("FOR CMD %s", command.description)
			//log.Printf("   - ERROR: %v", regError.FindStringSubmatch(app.mgmtBuffer[0]))
			//log.Printf("   - SUCCESS: %v", regSuccess.FindStringSubmatch(app.mgmtBuffer[0]))

			if matches := regError.FindStringSubmatch(app.mgmtBuffer[0]); len(matches) > 0 {
				//log.Printf("ERROR %s", app.mgmtBuffer[0])
				command.channel <- AwaitedResponse{
					body:  matches[1],
					error: true,
				}
				app.waitingCommands = app.waitingCommands[1:]
				app.mgmtBuffer = app.mgmtBuffer[1:]
				return 1
			} else if matches = regSuccess.FindStringSubmatch(app.mgmtBuffer[0]); len(matches) > 0 {
				//log.Printf("SUCCESS %s", app.mgmtBuffer[0])
				command.channel <- AwaitedResponse{
					body:  matches[1],
					error: false,
				}
				app.waitingCommands = app.waitingCommands[1:]
				app.mgmtBuffer = app.mgmtBuffer[1:]
				return 1
			}
		} else {
			if firstWord == "ERROR" {
				log.Printf("skipped ERROR %s", app.mgmtBuffer[0])
				app.mgmtBuffer = app.mgmtBuffer[1:]
				return 1
			} else {
				log.Printf("skipped SUCCESS %s", app.mgmtBuffer[0])
				app.mgmtBuffer = app.mgmtBuffer[1:]
				return 1
			}
		}
	}

	if !strings.HasPrefix(firstWord, "TITLE") {
		log.Printf("buf[%d,%d,%s} (%s)", len(app.mgmtBuffer), len(app.waitingCommands), firstWord, app.mgmtBuffer[len(app.mgmtBuffer)-1])
	}

	if regStatus3.MatchString(app.mgmtBuffer[0]) {
		//log.Printf("matched %s", app.mgmtBuffer[0])
		if lastLine == "END" {
			activeConnections := app.mgmtConnectedUsersParser3(app.mgmtBuffer)
			app.mgmtBuffer = make([]string, 0)
			app.synchroConnections(activeConnections)
			app.broadcast(WebsocketPacket{Stream: "users", Data: app.clients})
			//log.Printf("currently active clients %d", len(app.activeClients))
			return 1
		//} else {
		//	log.Printf("skipped to %d", len(app.mgmtBuffer))
		}
	} else if startCommand := regCommand.FindStringSubmatch(app.mgmtBuffer[0]); len(startCommand) > 0 {
		//log.Printf("matched command %v", startCommand)
		if startCommand[1] == "INFO" {
			if lastLine == "END" {
				app.handleVersion(app.mgmtBuffer)
				app.mgmtBuffer = make([]string, 0)
				return 1
			}
		} else if startCommand[1] == "CLIENT" {
			if lastLine == ">CLIENT:ENV,END" {
				app.handleNewClientEvent(app.mgmtBuffer)
				//app.updateConnections(app.activeConnections)
				app.mgmtBuffer = make([]string, 0)
				return 1
			}
		} else {
			log.Printf("unrecognized command %v", startCommand)
		}
	} else if lastLine == "END" {
		log.Printf("END of unrecognized packet '%v'", app.mgmtBuffer)
		app.mgmtBuffer = make([]string, 0)
		return 1
	} else {
		log.Printf("remaining lines '%v'", app.mgmtBuffer)
	}
	return 0
}

var regByteCount = regexp.MustCompile(`^>BYTECOUNT_CLI:([0-9]+),([0-9]+),([0-9]+)$`)

func (app *OvpnAdmin) handleBytecountUpdate(line string) {
	matches := regByteCount.FindStringSubmatch(line)
	if len(matches) <= 0 {
		log.Errorf("error parsing bytecount %v", line)
	}
	//log.Printf("parsed bytecount %v", matches)
	clientId, _ := strconv.ParseInt(matches[1], 10, 64)
	bytesReceive, _ := strconv.ParseInt(matches[2], 10, 64)
	bytesSent, _ := strconv.ParseInt(matches[3], 10, 64)

	for _, u := range app.clients {
		for _, c := range u.Connections {
			if c.ClientId == clientId {
				duration := time.Now().UnixMilli() - c.lastByteReceived.UnixMilli()
				if duration > 0 {
					//log.Infof("duration between sample", duration)
					c.SpeedBytesSent = (bytesSent - c.BytesSent) * 1000 / duration
					c.SpeedBytesReceived = (bytesReceive - c.BytesReceived) * 1000 / duration
					//log.Infof("duration [%s] between sample %d, => %d, %d", u.Username, duration, c.SpeedBytesSent, c.SpeedBytesReceived)
				}
				c.BytesSent = bytesSent
				c.BytesReceived = bytesReceive
				c.lastByteReceived = time.Now()
				app.triggerBroadcastUser(u)
				return
			}
		}
	}
	log.Warnf("Cant find client %d to update %d/%d", clientId, bytesSent, bytesReceive)
}

func (app *OvpnAdmin) triggerBroadcastUser(user *ClientCertificate) {
	if user == nil {
		return
	}
	for _, u := range app.updatedUsers {
		if u == user {
			return
		}
	}
	app.updatedUsers = append(app.updatedUsers, user)
}

func (app *OvpnAdmin) handleVersion(lines []string) {
	re := regexp.MustCompile("OpenVPN Version: OpenVPN ([0-9]+\\.[0-9]+\\.[0-9]+) ")

	for _, line := range lines {
		//log.Printf("-- INFO '%v'", line)
		parts := re.FindStringSubmatch(line)
		if len(parts) > 0 {
			version = parts[1]
		}
	}
}

var regClientEnv = regexp.MustCompile("^>CLIENT:ENV,([^=]*)=(.*)")
var regClientEstablished = regexp.MustCompile("^>CLIENT:ESTABLISHED,(.*)")

func (app *OvpnAdmin) handleNewClientEvent(lines []string) {
	//log.Printf("CLIENT '%v'", lines)
	var client = new(VpnClientConnection)
	var trustedAddress string
	var trustedPort int64

	if matches := regClientEstablished.FindStringSubmatch(lines[0]); len(matches) > 0 {
		if n64, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
			client.ClientId = n64
		}
	}

	for _, line := range lines {
		if matches := regClientEnv.FindStringSubmatch(line); len(matches) > 0 {
			key := matches[1]
			value := matches[2]

			//log.Printf("CLIENT ENV '%s' => '%s'", key, value)
			if key == "common_name" {
				client.commonName = value
			} else if key == "trusted_ip" {
				trustedAddress = value
			} else if key == "trusted_port" {
				if n32, err := strconv.ParseInt(value, 10, 64); err == nil {
					trustedPort = n32
				}
			} else if key == "ifconfig_pool_remote_ip" {	// TODO: add ipv6
				client.VirtualAddress = &value
			} else if key == "time_ascii" {
				client.ConnectedSince = &value
				client.LastRef = &value
			}
		}
	}
	if client.ClientId > 0 && len(client.commonName) > 0 {
		if len(trustedAddress) > 0 && trustedPort > 0 {
			client.RealAddress = fmt.Sprintf("%s:%d", trustedAddress, trustedPort)
		}

		//client.ConnectedSince =
		client.Nodes = make([]NodeInfo, 0)
		client.Networks = make([]Network, 0)
		app.addToClientConnections(client)

		log.Printf("Push connection '%v'", client)
		user := app.getCertificate(client.commonName)
		if user != nil {
			updatedUsers := []*ClientCertificate{user}
			app.broadcast(WebsocketPacket{Stream: "user.update", Data: updatedUsers})
			//log.Warnf("updating single user %s", user.Username)
			app.broadcast(WebsocketPacket{Stream: "user.update." + user.Username, Data: updatedUsers[0]})
		}
	} else {
		log.Printf("Skipped client '%v'", lines)
	}
}

func (app *OvpnAdmin) addToClientConnections(client *VpnClientConnection) {
	for _, certificate := range app.clients {
		if certificate.Username == client.commonName {
			certificate.Connections = append(certificate.Connections, client)
			return
		}
	}
	log.Printf("Can't find certificate for %s", client.commonName)
	//oAdmin.activeConnections = append(oAdmin.activeConnections, client)
}

func (app *OvpnAdmin) killAndRemoveConnection(client *ClientCertificate, conn *VpnClientConnection) error {
	if err := app.killConnection(conn); err != nil {
		return err
	}
	for _, c := range app.clients {
		for j, co := range c.Connections {
			if co == conn {
				log.Infof("removed active connection %d", c)
				c.Connections = append(c.Connections[0:j], c.Connections[j+1:]...)
				//app.updateConnections(app.activeConnections)
				app.triggerBroadcastUser(client)
				break
			}
		}
	}

	return nil
}

type AwaitedResponse struct {
	body   string
	error  bool
}

type WaitingCommand struct {
	description string
	channel chan AwaitedResponse
}

func (app *OvpnAdmin) sendManagementCommandWaitResponse(cmd string) AwaitedResponse {
	waitingCommand := WaitingCommand{
		description: cmd,
		channel: make(chan AwaitedResponse),
	}
	app.waitingCommands = append(app.waitingCommands, waitingCommand)
	//log.Infof("waiting for response of command %s", cmd)
	app.sendManagementCommand(cmd)
	resp := <- waitingCommand.channel
	//log.Infof("got response: %s", resp.body)
	return resp
}

func (app *OvpnAdmin) sendManagementCommand(cmd string) {
	if app.conn == nil {
		log.Errorf("Fail to send command %s, not connected", cmd)
		return
	}
	_, err := app.conn.Write([]byte(cmd + "\n"))
	if err != nil {
		log.Errorf("Fail to send command %s", cmd)
		app.conn.Close()
		return
	}
	app.broadcast(WebsocketPacket{Stream: "write", Data: cmd})
	//log.Printf("sendManagementCommand %s", cmd)
}

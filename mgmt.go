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

func (oAdmin *OvpnAdmin) mgmtConnectedUsersParser3(lines []string) []*ClientStatus {
	var u = make([]*ClientStatus, 0)
	//isClientList := false
	//isRouteTable := false
	for _, txt := range lines {
		if regexp.MustCompile(`^CLIENT_LIST\t`).MatchString(txt) {
			user := strings.Split(txt, "\t")

			bytesReceive, _ := strconv.ParseInt(user[5], 10, 64)
			bytesSent, _ := strconv.ParseInt(user[6], 10, 64)
			clientId, _ := strconv.ParseInt(user[10], 10, 64)
			//log.Infof("parsed client %s id %d from", user[1], clientId, user[10])
			clientStatus := new(ClientStatus)
			clientStatus.commonName = user[1]
			clientStatus.RealAddress = user[2]
			clientStatus.VirtualAddress = user[3]
			clientStatus.VirtualAddressIPv6 = user[4]
			clientStatus.BytesReceived = bytesReceive
			clientStatus.BytesSent = bytesSent
			clientStatus.ConnectedSince = user[7]
			clientStatus.ClientId = clientId

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
						u[i].Nodes = append(u[i].Nodes, NodeInfo{
							Address: peerAddress[:len(peerAddress)-1],
							LastSeen: userConnectedSince,
						})
					} else if strings.Contains(peerAddress, "/") {
						u[i].Networks = append(u[i].Networks, Network{
							Address: peerAddress,
							LastSeen: userConnectedSince,
						})
					} else {

						//u[i].VirtualAddress = peerAddress
						u[i].LastRef = userConnectedSince
					}
					//ovpnClientConnectionInfo.WithLabelValues(user[1], user[0]).Set(float64(parseDateToUnix(oAdmin.mgmtStatusTimeFormat, user[3])))
					break
				}
			}
		}
	}
	return u
}

func (oAdmin *OvpnAdmin) killUserConnections(serverName *OpenvpnClient) {
	oAdmin.sendManagementCommand(fmt.Sprintf("kill %s\n", serverName.Username))
}

func (oAdmin *OvpnAdmin) killConnection(serverName *ClientStatus) error {
	resp := oAdmin.sendManagementCommandWaitResponse(fmt.Sprintf("kill %s\n", serverName.RealAddress))	// address:port
	if resp.error {
		return errors.New(resp.body)
	}
	return nil
}

func (oAdmin *OvpnAdmin) connectToManagementInterface() {
	go func() {
		for {
			time.Sleep(time.Duration(28) * time.Second)
			oAdmin.sendManagementCommand("status 3")
		}
	}()
	go func() {
		for {
			time.Sleep(time.Duration(2) * time.Second)
			if len(oAdmin.updatedUsers) > 0 {
				oAdmin.broadcast(WebsocketPacket{Stream: "user.update", Data: oAdmin.updatedUsers})
				oAdmin.updatedUsers = make([]*OpenvpnClient, 0)
			}
		}
	}()
	for {
		if len(oAdmin.mgmtInterface) == 0 {
			time.Sleep(time.Duration(30) * time.Second)
			continue
		}
		conn, err := net.Dial("tcp", oAdmin.mgmtInterface)
		if err != nil {
			log.Warnf("openvpn mgmt interface is not reachable at %s", oAdmin.mgmtInterface)
			time.Sleep(time.Duration(30) * time.Second)
			continue
		}
		oAdmin.conn = conn
		go func() {
			oAdmin.sendManagementCommand("version")
			oAdmin.sendManagementCommand("status 3")
			resp := oAdmin.sendManagementCommandWaitResponse("bytecount 5")
			log.Infof("register bytecount 5 returns: %s", resp)
		}()

		//oAdmin.sendManagementCommand("client-auth")

		scanner := bufio.NewScanner(oAdmin.conn)

		for scanner.Scan() {
			line := scanner.Text()

			// append to buffer and handle lines if recognized
			oAdmin.mgmtBuffer = append(oAdmin.mgmtBuffer, line)
			//log.Printf("live '%s'", line)
			oAdmin.broadcast(WebsocketPacket{Stream: "read", Data: line})
			for oAdmin.processMgmtBuffer() > 0 {

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

func (oAdmin *OvpnAdmin) processMgmtBuffer() int {
	if len(oAdmin.mgmtBuffer) == 0 {
		return 0
	}
	firstWord := strings.TrimPrefix(strings.SplitN(oAdmin.mgmtBuffer[0], ":", 2)[0], ">")
	lastLine := oAdmin.mgmtBuffer[len(oAdmin.mgmtBuffer)-1]

	if firstWord == "BYTECOUNT_CLI" {
		oAdmin.handleBytecountUpdate(oAdmin.mgmtBuffer[0])
		oAdmin.mgmtBuffer = oAdmin.mgmtBuffer[1:]
		return 1
	}

	if firstWord == "ERROR" || firstWord == "SUCCESS" {
		if len(oAdmin.waitingCommands) > 0 {
			command := oAdmin.waitingCommands[0]
			//log.Printf("FOR CMD %s", command.description)
			//log.Printf("   - ERROR: %v", regError.FindStringSubmatch(oAdmin.mgmtBuffer[0]))
			//log.Printf("   - SUCCESS: %v", regSuccess.FindStringSubmatch(oAdmin.mgmtBuffer[0]))

			if matches := regError.FindStringSubmatch(oAdmin.mgmtBuffer[0]); len(matches) > 0 {
				//log.Printf("ERROR %s", oAdmin.mgmtBuffer[0])
				command.channel <- AwaitedResponse{
					body:  matches[1],
					error: true,
				}
				oAdmin.waitingCommands = oAdmin.waitingCommands[1:]
				oAdmin.mgmtBuffer = oAdmin.mgmtBuffer[1:]
				return 1
			} else if matches = regSuccess.FindStringSubmatch(oAdmin.mgmtBuffer[0]); len(matches) > 0 {
				//log.Printf("SUCCESS %s", oAdmin.mgmtBuffer[0])
				command.channel <- AwaitedResponse{
					body:  matches[1],
					error: false,
				}
				oAdmin.waitingCommands = oAdmin.waitingCommands[1:]
				oAdmin.mgmtBuffer = oAdmin.mgmtBuffer[1:]
				return 1
			}
		} else {
			if firstWord == "ERROR" {
				log.Printf("skipped ERROR %s", oAdmin.mgmtBuffer[0])
				oAdmin.mgmtBuffer = oAdmin.mgmtBuffer[1:]
				return 1
			} else {
				log.Printf("skipped SUCCESS %s", oAdmin.mgmtBuffer[0])
				oAdmin.mgmtBuffer = oAdmin.mgmtBuffer[1:]
				return 1
			}
		}
	}

	if !strings.HasPrefix(firstWord, "TITLE") {
		log.Printf("buf[%d,%d,%s} (%s)", len(oAdmin.mgmtBuffer), len(oAdmin.waitingCommands), firstWord, oAdmin.mgmtBuffer[len(oAdmin.mgmtBuffer)-1])
	}

	if regStatus3.MatchString(oAdmin.mgmtBuffer[0]) {
		//log.Printf("matched %s", oAdmin.mgmtBuffer[0])
		if lastLine == "END" {
			oAdmin.activeConnections = oAdmin.mgmtConnectedUsersParser3(oAdmin.mgmtBuffer)
			oAdmin.mgmtBuffer = make([]string, 0)
			oAdmin.updateConnections(oAdmin.activeConnections)
			oAdmin.broadcast(WebsocketPacket{Stream: "users", Data: oAdmin.clients})
			//log.Printf("currently active clients %d", len(oAdmin.activeClients))
			return 1
		//} else {
		//	log.Printf("skipped to %d", len(oAdmin.mgmtBuffer))
		}
	} else if startCommand := regCommand.FindStringSubmatch(oAdmin.mgmtBuffer[0]); len(startCommand) > 0 {
		//log.Printf("matched command %v", startCommand)
		if startCommand[1] == "INFO" {
			if lastLine == "END" {
				oAdmin.handleVersion(oAdmin.mgmtBuffer)
				oAdmin.mgmtBuffer = make([]string, 0)
				return 1
			}
		} else if startCommand[1] == "CLIENT" {
			if lastLine == ">CLIENT:ENV,END" {
				oAdmin.handleNewClientEvent(oAdmin.mgmtBuffer)
				oAdmin.updateConnections(oAdmin.activeConnections)
				oAdmin.mgmtBuffer = make([]string, 0)
				return 1
			}
		} else {
			log.Printf("unrecognized command %v", startCommand)
		}
	} else if lastLine == "END" {
		log.Printf("END of unrecognized packet '%v'", oAdmin.mgmtBuffer)
		oAdmin.mgmtBuffer = make([]string, 0)
		return 1
	} else {
		log.Printf("remaining lines '%v'", oAdmin.mgmtBuffer)
	}
	return 0
}

var regByteCount = regexp.MustCompile(`^>BYTECOUNT_CLI:([0-9]+),([0-9]+),([0-9]+)$`)

func (oAdmin *OvpnAdmin) handleBytecountUpdate(line string) {
	if matches := regByteCount.FindStringSubmatch(line); len(matches) > 0 {
		//log.Printf("parsed bytecount %v", matches)
		clientId, _ := strconv.ParseInt(matches[1], 10, 64)
		bytesReceive, _ := strconv.ParseInt(matches[2], 10, 64)
		bytesSent, _ := strconv.ParseInt(matches[3], 10, 64)

		for _, u := range oAdmin.clients {
			for _, c := range u.Connections {
				if c.ClientId == clientId {
					c.BytesSent = bytesSent
					c.BytesReceived = bytesReceive
					oAdmin.addUpdatedUsers(u)
					return
				}
			}
		}
		log.Warnf("Cant find client %d to update %d/%d", clientId, bytesSent, bytesReceive)
	} else {
		log.Errorf("error parsing bytecount %v", line)
	}
}

func (oAdmin *OvpnAdmin) addUpdatedUsers(user *OpenvpnClient) {
	if user == nil {
		return
	}
	for _, u := range oAdmin.updatedUsers {
		if u == user {
			return
		}
	}
	oAdmin.updatedUsers = append(oAdmin.updatedUsers, user)
}

func (oAdmin *OvpnAdmin) handleVersion(lines []string) {
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

func (oAdmin *OvpnAdmin) handleNewClientEvent(lines []string) {
	//log.Printf("CLIENT '%v'", lines)
	var client = new(ClientStatus)
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
				client.VirtualAddress = value
			} else if key == "time_ascii" {
				client.ConnectedSince = value
				client.LastRef = value
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
		oAdmin.activeConnections = append(oAdmin.activeConnections, client)
		log.Printf("Push connection '%v'", client)
		user := oAdmin.getUser(client.commonName)
		if user != nil {
			updatedUsers := []*OpenvpnClient{user}
			oAdmin.broadcast(WebsocketPacket{Stream: "user.update", Data: updatedUsers})
		}
	} else {
		log.Printf("Skipped client '%v'", lines)
	}
}

func (oAdmin *OvpnAdmin) killAndRemoveConnection(client *OpenvpnClient, conn *ClientStatus) error {
	if err := oAdmin.killConnection(conn); err != nil {
		return err
	}
	for i, c := range oAdmin.activeConnections {
		if c.ClientId == conn.ClientId {
			log.Infof("removed active connection %d", c)
			oAdmin.activeConnections = append(oAdmin.activeConnections[0:i], oAdmin.activeConnections[i+1:]...)
			oAdmin.updateConnections(oAdmin.activeConnections)
			oAdmin.addUpdatedUsers(client)
			break
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

func (oAdmin *OvpnAdmin) sendManagementCommandWaitResponse(cmd string) AwaitedResponse {
	waitingCommand := WaitingCommand{
		description: cmd,
		channel: make(chan AwaitedResponse),
	}
	oAdmin.waitingCommands = append(oAdmin.waitingCommands, waitingCommand)
	//log.Infof("waiting for response of command %s", cmd)
	oAdmin.sendManagementCommand(cmd)
	resp := <- waitingCommand.channel
	//log.Infof("got response: %s", resp.body)
	return resp
}

func (oAdmin *OvpnAdmin) sendManagementCommand(cmd string) {
	if oAdmin.conn == nil {
		log.Errorf("Fail to send command %s, not connected", cmd)
		return
	}
	_, err := oAdmin.conn.Write([]byte(cmd + "\n"))
	if err != nil {
		log.Errorf("Fail to send command %s", cmd)
		oAdmin.conn.Close()
		return
	}
	oAdmin.broadcast(WebsocketPacket{Stream: "write", Data: cmd})
	//log.Printf("sendManagementCommand %s", cmd)
}

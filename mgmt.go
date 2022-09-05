package main

import (
	"bufio"
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

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(serverName *ClientStatus) {
	conn, err := net.Dial("tcp", oAdmin.mgmtInterface)
	if err != nil {
		log.Errorf("openvpn mgmt interface is not reachable at addr %s", oAdmin.mgmtInterface)
		return
	}
	oAdmin.mgmtRead(conn) // read welcome message
	conn.Write([]byte(fmt.Sprintf("kill %s\n", serverName.commonName)))
	ret, err := oAdmin.mgmtRead(conn)
	fmt.Printf("%v", ret)
	conn.Close()
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
			time.Sleep(time.Duration(5) * time.Second)
			if len(oAdmin.updatedUsers) > 0 {
				oAdmin.broadcast(WebsocketPacket{Stream: "user.update", Data: oAdmin.updatedUsers})
				oAdmin.updatedUsers = make([]*OpenvpnClient, 0)
			}
		}
	}()
	for {
		conn, err := net.Dial("tcp", oAdmin.mgmtInterface)
		if err != nil {
			log.Warnf("openvpn mgmt interface is not reachable at %s", oAdmin.mgmtInterface)
			time.Sleep(time.Duration(30) * time.Second)
			continue
		}
		oAdmin.conn = conn
		oAdmin.sendManagementCommand("version")
		oAdmin.sendManagementCommand("status 3")
		oAdmin.sendManagementCommand("bytecount 5")
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

func (oAdmin *OvpnAdmin) processMgmtBuffer() int {
	if len(oAdmin.mgmtBuffer) == 0 {
		return 0
	}
	//log.Printf("pending lines %d (%s)", len(oAdmin.mgmtBuffer), oAdmin.mgmtBuffer[0])

	if oAdmin.mgmtBuffer[0] == "SUCCESS: bytecount interval changed" {
		oAdmin.mgmtBuffer = oAdmin.mgmtBuffer[1:]
		return 1
	} else if regStatus3.MatchString(oAdmin.mgmtBuffer[0]) {
		//log.Printf("matched %s", oAdmin.mgmtBuffer[0])
		if subLines := findEndOfPacketLine(&oAdmin.mgmtBuffer, "END"); len(subLines) > 0 {
			oAdmin.activeClients = oAdmin.mgmtConnectedUsersParser3(subLines)
			oAdmin.updateConnections()
			oAdmin.broadcast(WebsocketPacket{Stream: "users", Data: oAdmin.clients})
			//log.Printf("currently active clients %d", len(oAdmin.activeClients))
			return 1
		//} else {
		//	log.Printf("skipped to %d", len(oAdmin.mgmtBuffer))
		}
	} else if startCommand := regCommand.FindStringSubmatch(oAdmin.mgmtBuffer[0]); len(startCommand) > 0 {
		//log.Printf("matched command %v", startCommand)
		if startCommand[1] == "INFO" {
			if subLines := findEndOfPacketLine(&oAdmin.mgmtBuffer, "END"); len(subLines) > 0 {
				oAdmin.handleVersion(subLines)
				return 1
			}
		} else if startCommand[1] == "CLIENT" {
			if subLines := findEndOfPacketLine(&oAdmin.mgmtBuffer, "END"); len(subLines) > 0 {
				oAdmin.handleClientEvent(subLines)
				return 1
			}
		} else if startCommand[1] == "BYTECOUNT_CLI" {
			oAdmin.handleBytecountUpdate(oAdmin.mgmtBuffer[0])
			oAdmin.mgmtBuffer = oAdmin.mgmtBuffer[1:]
			return 1
		} else {
			log.Printf("unrecognized command %v", startCommand)
		}
	} else if oAdmin.mgmtBuffer[len(oAdmin.mgmtBuffer)-1] == "END" {
		log.Printf("END of unrecognized packet '%v'", oAdmin.mgmtBuffer)
		oAdmin.mgmtBuffer = make([]string, 0)
		return 1
	} else {
		log.Printf("remaining lines '%v'", oAdmin.mgmtBuffer)
	}
	return 0
}

func findEndOfPacketLine(lines *[]string, search string) []string {
	ret := make([]string, 0)
	for i, line := range *lines {
		if line == search {
			ret = (*lines)[0:i]
			*lines = (*lines)[i+1:]
			return ret
		}
	}
	return ret
}

var regByteCount = regexp.MustCompile(`^>BYTECOUNT_CLI:([0-9]+),([0-9]+),([0-9]+)$`)

func (oAdmin *OvpnAdmin) handleBytecountUpdate(line string) {
	if matches := regByteCount.FindStringSubmatch(line); len(matches) > 0 {
		//log.Printf("parsed bytecount %v", matches)
		clientId, _ := strconv.ParseInt(matches[1], 10, 64)
		bytesReceive, _ := strconv.ParseInt(matches[2], 10, 64)
		bytesSent, _ := strconv.ParseInt(matches[3], 10, 64)

		for _, u := range oAdmin.activeClients {
			if u.ClientId == clientId {
				u.BytesSent = bytesSent
				u.BytesReceived = bytesReceive
				oAdmin.addToUpdatedUsers(u)
				return
			}
		}
		log.Warnf("Cant find client %d to update %d/%d", clientId, bytesSent, bytesReceive)
	} else {
		log.Errorf("error parsing bytecount %v", line)
	}
}

func (oAdmin *OvpnAdmin) addToUpdatedUsers(client *ClientStatus) {
	for _, user := range oAdmin.clients {
		for _, conn := range user.Connections {
			if conn.ClientId == client.ClientId {
				oAdmin.updatedUsers = append(oAdmin.updatedUsers, user)
				return
			}
		}
	}
}

func (oAdmin *OvpnAdmin) handleVersion(lines []string) {
	re := regexp.MustCompile("OpenVPN Version: OpenVPN ([0-9]+\\.[0-9]+\\.[0-9]+) ")

	for _, line := range lines {
		log.Printf("-- INFO '%v'", line)
		parts := re.FindStringSubmatch(line)
		if len(parts) > 0 {
			version = parts[1]
		}
	}

	if strings.HasPrefix(version, "2.4") {
		oAdmin.mgmtStatusTimeFormat = time.ANSIC
		//log.Printf("mgmtStatusTimeFormat changed: %s", oAdmin.mgmtStatusTimeFormat)
	}
}

func (oAdmin *OvpnAdmin) handleClientEvent(lines []string) {
	log.Printf("CLIENT '%v'", lines)
}

func (oAdmin *OvpnAdmin) sendManagementCommand(cmd string) {
	_, err := oAdmin.conn.Write([]byte(cmd + "\n"))
	if err != nil {
		log.Errorf("Fail to send command %s", cmd)
		oAdmin.conn.Close()
		return
	}
	oAdmin.broadcast(WebsocketPacket{Stream: "write", Data: cmd})
	//log.Printf("sendManagementCommand %s", cmd)
}

func (oAdmin *OvpnAdmin) mgmtRead(conn net.Conn) (string, error) {
	recvData := make([]byte, 32768)
	var out string
	var n int
	var err error
	for {
		n, err = conn.Read(recvData)
		if n <= 0 || err != nil {
			return "", err
		} else {
			out += string(recvData[:n])
			if strings.Contains(out, "type 'help' for more info") || strings.Contains(out, "END") || strings.Contains(out, "SUCCESS:") || strings.Contains(out, "ERROR:") {
				break
			}
		}
	}
	return out, nil
}

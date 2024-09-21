package mgmt

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"regexp"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
	"strconv"
	"strings"
	"time"
)

type AwaitedResponse struct {
	body  string
	error bool
}

type WaitingCommand struct {
	description string
	channel     chan AwaitedResponse
}

type OpenVPNmgmt struct {
	Version              string
	buffer               []string
	Conn                 net.Conn
	TriggerBroadcastUser func(certificate *model.Device)
	GetConnection        func(int64) (*model.Device, *openvpn.VpnConnection)
	GetUserConnection    func(string, int64) (*model.Device, *openvpn.VpnConnection)
	WaitingCommands      []WaitingCommand
	SynchroConnections   func([]*openvpn.VpnConnection)
	BroadcastWritePacket func(line string)
	BroadcastReadPacket  func(line string)
	AddClientConnection  func(connection *openvpn.VpnConnection)
}

var (
	regByteCount         = regexp.MustCompile(`^>BYTECOUNT_CLI:([0-9]+),([0-9]+),([0-9]+)$`)
	regCommand           = regexp.MustCompile("^>([A-Z_]+):")
	regStatus3           = regexp.MustCompile("^TITLE\tOpenVPN\\s+[0-9]+\\.[0-9]+\\.[0-9]+\\s+")
	regError             = regexp.MustCompile("^ERROR:\\s+(.*)")
	regSuccess           = regexp.MustCompile("^SUCCESS:\\s+(.*)")
	regClientEnv         = regexp.MustCompile("^>CLIENT:ENV,([^=]*)=(.*)")
	regClientEstablished = regexp.MustCompile("^>CLIENT:ESTABLISHED,(.*)")
)

func (mgmt *OpenVPNmgmt) HandleMessages() {
	//app.sendManagementCommand("client-auth")

	scanner := bufio.NewScanner(mgmt.Conn)

	for scanner.Scan() {
		line := scanner.Text()

		// append to buffer and handle lines if recognized
		mgmt.buffer = append(mgmt.buffer, line)
		//log.Printf("==> live '%s'", line)
		//log.Printf("  > buffer %s", mgmt.buffer)
		mgmt.BroadcastReadPacket(line)
		for mgmt.processMgmtBuffer() > 0 {

		}
		//ovpnClientBytesSent.Reset()
		//ovpnClientBytesReceived.Reset()
		//ovpnClientConnectionFrom.Reset()
		//ovpnClientConnectionInfo.Reset()
		//ovpnClientCertificateExpire.Reset()
	}
	log.Printf("end of scan")
}

func (mgmt *OpenVPNmgmt) MgmtConnectedUsersParser3(lines []string) []*openvpn.VpnConnection {
	var u = make([]*openvpn.VpnConnection, 0)
	reClientList := regexp.MustCompile(`^CLIENT_LIST\t`)
	reRoutingTable := regexp.MustCompile(`^ROUTING_TABLE\t`)
	//isClientList := false
	//isRouteTable := false
	for _, txt := range lines {
		if reClientList.MatchString(txt) {
			user := strings.Split(txt, "\t")

			bytesReceive, _ := strconv.ParseInt(user[5], 10, 64)
			bytesSent, _ := strconv.ParseInt(user[6], 10, 64)
			clientId, _ := strconv.ParseInt(user[10], 10, 64)
			//log.Infof("parsed client %s id %d from", user[1], clientId, user[10])
			var _, clientStatus = mgmt.GetUserConnection(user[1], clientId)
			if clientStatus == nil {
				clientStatus = new(openvpn.VpnConnection)
			}
			clientStatus.ClientId = clientId
			clientStatus.CommonName = user[1]
			clientStatus.RealAddress = user[2]
			clientStatus.BytesReceived = bytesReceive
			clientStatus.BytesSent = bytesSent
			clientStatus.LastByteReceived = time.Now()
			clientStatus.ConnectedSince = &user[7]
			clientStatus.VirtualAddress = &user[3]
			if user[4] != "" {
				clientStatus.VirtualAddressIPv6 = &user[4]
			}

			u = append(u, clientStatus)
		}
		if reRoutingTable.MatchString(txt) {
			user := strings.Split(txt, "\t")
			peerAddress := user[1]
			userName := user[2]
			realAddress := user[3]
			userConnectedSince := user[4]

			for i := range u {
				if u[i].CommonName == userName && u[i].RealAddress == realAddress {
					if strings.HasSuffix(peerAddress, "C") {
						addOrUpdateNode(u[i], peerAddress[:len(peerAddress)-1], userConnectedSince)
					} else if strings.Contains(peerAddress, "/") {
						addOrUpdateNetwork(u[i], peerAddress, userConnectedSince)
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

func addOrUpdateNode(clientStatus *openvpn.VpnConnection, peerAddress string, lastSeen string) {
	for i := range clientStatus.Nodes {
		if clientStatus.Nodes[i].Address == peerAddress {
			clientStatus.Nodes[i].LastSeen = lastSeen
			return
		}
	}
	clientStatus.Nodes = append(clientStatus.Nodes, openvpn.NodeInfo{
		Address:  peerAddress,
		LastSeen: lastSeen,
	})
}

func addOrUpdateNetwork(clientStatus *openvpn.VpnConnection, peerAddress string, lastSeen string) {
	for i := range clientStatus.Networks {
		if clientStatus.Networks[i].Address == peerAddress {
			clientStatus.Networks[i].LastSeen = lastSeen
			return
		}
	}
	clientStatus.Networks = append(clientStatus.Networks, openvpn.Network{
		Address:  peerAddress,
		LastSeen: lastSeen,
	})
}

func (mgmt *OpenVPNmgmt) processMgmtBuffer() int {
	if len(mgmt.buffer) == 0 {
		return 0
	}
	firstWord := strings.TrimPrefix(strings.SplitN(mgmt.buffer[0], ":", 2)[0], ">")
	lastLine := mgmt.buffer[len(mgmt.buffer)-1]

	if firstWord == "BYTECOUNT_CLI" {
		mgmt.HandleBytecountUpdate(mgmt.buffer[0])
		mgmt.buffer = mgmt.buffer[1:]
		return 1
	}

	if firstWord == "ERROR" || firstWord == "SUCCESS" {
		if len(mgmt.WaitingCommands) > 0 {
			command := mgmt.WaitingCommands[0]
			//log.Printf("FOR CMD %s", command.description)
			//log.Printf("   - ERROR: %v", regError.FindStringSubmatch(mgmt.buffer[0]))
			//log.Printf("   - SUCCESS: %v", regSuccess.FindStringSubmatch(mgmt.buffer[0]))

			if matches := regError.FindStringSubmatch(mgmt.buffer[0]); len(matches) > 0 {
				//log.Printf("ERROR %s", app.buffer[0])
				command.channel <- AwaitedResponse{
					body:  matches[1],
					error: true,
				}
				mgmt.WaitingCommands = mgmt.WaitingCommands[1:]
				mgmt.buffer = mgmt.buffer[1:]
				return 1
			} else if matches = regSuccess.FindStringSubmatch(mgmt.buffer[0]); len(matches) > 0 {
				//log.Printf("SUCCESS %s", app.buffer[0])
				command.channel <- AwaitedResponse{
					body:  matches[1],
					error: false,
				}
				mgmt.WaitingCommands = mgmt.WaitingCommands[1:]
				mgmt.buffer = mgmt.buffer[1:]
				return 1
			}
		} else {
			if firstWord == "ERROR" {
				log.Printf("skipped ERROR %s", mgmt.buffer[0])
				mgmt.buffer = mgmt.buffer[1:]
				return 1
			} else {
				log.Printf("skipped SUCCESS %s", mgmt.buffer[0])
				mgmt.buffer = mgmt.buffer[1:]
				return 1
			}
		}
	}

	//if !strings.HasPrefix(firstWord, "TITLE") {
	//	log.Printf("buf[%d,%d,%s} (%s)", len(app.buffer), len(app.WaitingCommands), firstWord, app.buffer[len(app.buffer)-1])
	//}

	if regStatus3.MatchString(mgmt.buffer[0]) {
		//log.Printf("matched %s", app.buffer[0])
		if lastLine == "END" {
			activeConnections := mgmt.MgmtConnectedUsersParser3(mgmt.buffer)
			//log.Printf("currently active clients %d", len(activeConnections))
			mgmt.buffer = make([]string, 0)
			mgmt.SynchroConnections(activeConnections)
			return 1
		}
	} else if startCommand := regCommand.FindStringSubmatch(mgmt.buffer[0]); len(startCommand) > 0 {
		//log.Printf("matched command %v", startCommand)
		if startCommand[1] == "INFO" {
			if lastLine == "END" {
				mgmt.handleVersion(mgmt.buffer)
				mgmt.buffer = make([]string, 0)
				return 1
			}
		} else if startCommand[1] == "CLIENT" {
			if lastLine == ">CLIENT:ENV,END" {
				mgmt.handleNewClientEvent(mgmt.buffer)
				//app.updateConnections(app.activeConnections)
				mgmt.buffer = make([]string, 0)
				return 1
			}
		} else if startCommand[1] == "NOTIFY" {
			log.Printf("notify %v", mgmt.buffer[0])
			mgmt.buffer = make([]string, 0)
			return 1
		} else {
			log.Printf("unrecognized command %v", startCommand)
			return 1
		}
	} else if lastLine == "END" {
		log.Printf("END of unrecognized packet '%v'", mgmt.buffer)
		mgmt.buffer = make([]string, 0)
		return 1
	} else {
		log.Printf("remaining lines '%v'", mgmt.buffer)
	}
	return 0
}

func (mgmt *OpenVPNmgmt) handleVersion(lines []string) {
	re := regexp.MustCompile("OpenVPN Version: OpenVPN ([0-9]+\\.[0-9]+\\.[0-9]+) ")

	for _, line := range lines {
		parts := re.FindStringSubmatch(line)
		if len(parts) > 0 {
			//log.Printf("-- INFO: Version '%s'", parts[1])
			mgmt.Version = parts[1]
		}
	}
}

func (mgmt *OpenVPNmgmt) HandleBytecountUpdate(line string) {
	matches := regByteCount.FindStringSubmatch(line)
	if len(matches) <= 0 {
		log.Printf("error parsing bytecount %v", line)
		return
	}
	//log.Printf("parsed bytecount %v", matches)
	clientId, _ := strconv.ParseInt(matches[1], 10, 64)
	bytesReceive, _ := strconv.ParseInt(matches[2], 10, 64)
	bytesSent, _ := strconv.ParseInt(matches[3], 10, 64)

	u, c := mgmt.GetConnection(clientId)
	if c != nil {
		duration := time.Now().UnixMilli() - c.LastByteReceived.UnixMilli()
		if duration > 0 {
			//log.Infof("duration between sample", duration)
			c.SpeedBytesSent = (bytesSent - c.BytesSent) * 1000 / duration
			c.SpeedBytesReceived = (bytesReceive - c.BytesReceived) * 1000 / duration
			//log.Infof("duration [%s] between sample %d, => %d, %d", u.CommonName, duration, c.SpeedBytesSent, c.SpeedBytesReceived)
		}
		c.BytesSent = bytesSent
		c.BytesReceived = bytesReceive
		c.LastByteReceived = time.Now()
		mgmt.TriggerBroadcastUser(u)
		//app.triggerBroadcastUser(u)
		return
	}
	log.Printf("Cant find client %d to update %d/%d", clientId, bytesSent, bytesReceive)
}

func (mgmt *OpenVPNmgmt) handleNewClientEvent(lines []string) {
	//log.Printf("CLIENT '%v'", lines)
	var client = new(openvpn.VpnConnection)
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
				client.CommonName = value
			} else if key == "trusted_ip" {
				trustedAddress = value
			} else if key == "trusted_port" {
				if n32, err := strconv.ParseInt(value, 10, 64); err == nil {
					trustedPort = n32
				}
			} else if key == "ifconfig_pool_remote_ip" { // TODO: add ipv6
				client.VirtualAddress = &value
			} else if key == "time_ascii" {
				client.ConnectedSince = &value
				client.LastRef = &value
			}
		}
	}
	if len(client.CommonName) > 0 {
		if len(trustedAddress) > 0 && trustedPort > 0 {
			client.RealAddress = fmt.Sprintf("%s:%d", trustedAddress, trustedPort)
		}

		//client.ConnectedSince =
		client.Nodes = make([]openvpn.NodeInfo, 0)
		client.Networks = make([]openvpn.Network, 0)
		mgmt.AddClientConnection(client)

	} else {
		log.Printf("Skipped client:")
		for _, line := range lines {
			log.Printf("    %s", line)
		}
	}
}

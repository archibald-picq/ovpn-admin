package mgmt

import (
	"errors"
	"fmt"
	"log"
	"rpiadm/backend/model"
	"rpiadm/backend/openvpn"
)

func (mgmt *OpenVPNmgmt) SendManagementCommand(cmd string) {
	if mgmt.Conn == nil {
		log.Printf("Fail to send command %s, not connected", cmd)
		return
	}
	//log.Printf("<== send '%s'", cmd)
	//log.Printf("  (%d waiting commands, %d buffer size) %v", len(mgmt.WaitingCommands), len(mgmt.buffer), mgmt.WaitingCommands)
	_, err := mgmt.Conn.Write([]byte(cmd + "\n"))
	if err != nil {
		log.Printf("Fail to send command '%s': %v", cmd, err)
		mgmt.Conn.Close()
		return
	}
	mgmt.BroadcastWritePacket(cmd)
	//app.broadcast(WebsocketPacket{Stream: "write", Data: cmd})
	//log.Printf("sendManagementCommand %s", cmd)
}

func (mgmt *OpenVPNmgmt) SendManagementCommandWaitResponse(cmd string) AwaitedResponse {
	waitingCommand := WaitingCommand{
		description: cmd,
		channel:     make(chan AwaitedResponse),
	}
	mgmt.WaitingCommands = append(mgmt.WaitingCommands, waitingCommand)
	//log.Printf("waiting for response of command %s", cmd)
	mgmt.SendManagementCommand(cmd)
	resp := <-waitingCommand.channel
	//log.Printf("got response: %s", resp.body)
	return resp
}

func (mgmt *OpenVPNmgmt) KillConnection(serverName *openvpn.VpnConnection) error {
	resp := mgmt.SendManagementCommandWaitResponse(fmt.Sprintf("client-kill %d\n", serverName.ClientId)) // address:port
	if resp.error {
		return errors.New(resp.body)
	}
	return nil
}

func (mgmt *OpenVPNmgmt) KillUserConnections(serverName *model.Device) {
	mgmt.SendManagementCommand(fmt.Sprintf("kill %s\n", serverName.Username))
}

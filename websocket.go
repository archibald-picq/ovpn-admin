package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"rpiadm/backend/model"
	"rpiadm/backend/rpi"
	"rpiadm/backend/rpi/cmd"
	"time"
)

type WebsocketPacket struct {
	Stream string      `json:"stream"`
	Data   interface{} `json:"data"`
}

func (app *OvpnAdmin) checkWebsocketOrigin(r *http.Request) bool {
	return true
}
func (app *OvpnAdmin) removeConnection(conn *websocket.Conn) {
	//log.Printf("Websocket client disconnected, removing connection %s", conn.RemoteAddr().String())
	conn.Close()
	var found *rpi.WsSafeConn
	for i, c := range app.wsConnections {
		if c.Ws == conn {
			found = c
			app.wsConnections = remove(app.wsConnections, i)
		}
	}
	if found == nil {
		log.Printf("Websocket client NOT found, can't remove from Rpic")
		return
	}
	//log.Printf("Websocket client found for removal with role %s", found.Role)
	if found.Role == "rpic" {
		for _, client := range app.clients {
			for j, rpic := range client.Rpic {
				if rpic.Ws.Ws == found.Ws {
					app.onRemoveRpi(client, client.Rpic[j])
					client.Rpic = removeRpi(client.Rpic, j)
					log.Printf("rpic disconnected, pool size: %r", len(client.Rpic))
					app.broadcast(WebsocketPacket{Stream: "user.update." + client.Username, Data: client})
					app.broadcast(WebsocketPacket{Stream: "user.update." + client.Username + ".rpic", Data: client.Rpic})
					break
				}
			}
		}
		log.Printf("rpic disconnected")
	}
}

func remove(s []*rpi.WsSafeConn, i int) []*rpi.WsSafeConn {
	return append(s[0:i], s[i+1:]...)
	//s[i] = s[len(s)-1]
	//return s[:len(s)-1]
}
func removeRpi(s []*rpi.RpiConnection, i int) []*rpi.RpiConnection {
	return append(s[0:i], s[i+1:]...)
	//s[i] = s[len(s)-1]
	//return s[:len(s)-1]
}
func (app *OvpnAdmin) websocket(w http.ResponseWriter, r *http.Request) {
	//for k, v := range r.Header {
	//	log.Printf( "Header field %q, Value %q\n", k, v)
	//}
	xForwardedFor := r.Header.Get("x-forwarded-for")
	xForwardedProto := r.Header.Get("x-forwarded-proto")
	userAgent := r.Header.Get("user-agent")
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade error:", err)
		return
	}
	defer app.removeConnection(c)
	wsSafe := new(rpi.WsSafeConn)
	wsSafe.Ws = c
	wsSafe.Last = time.Now()
	wsSafe.Next = time.AfterFunc(time.Duration(30)*time.Second, func() {
		next(wsSafe)
	})
	wsSafe.XForwardedFor = xForwardedFor
	wsSafe.XForwardedProto = xForwardedProto
	wsSafe.UserAgent = userAgent
	app.wsConnections = append(app.wsConnections, wsSafe)
	//log.Printf("connected, pool size: %d", len(app.wsConnections))

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			//log.Println("read:", err)
			break
		}
		wsSafe.Last = time.Now()
		//switch messageType {
		//case websocket.TextMessage:
		//	log.Printf("recv (text): %s", bytes.TrimRight(message, "\n"))
		//case websocket.BinaryMessage:
		//	log.Printf("recv (binary): %s", message)
		//}
		app.handleWebsocketMessage(wsSafe, message)
	}
}

func (app *OvpnAdmin) handleWebsocketMessage(conn *rpi.WsSafeConn, message []byte) {
	var errResp cmd.WebsocketErrorResponse
	//log.Printf("unmarshal %s", string(message))
	err := json.Unmarshal(message, &errResp)
	if err == nil && len(errResp.Error.Message) > 0 {
		log.Printf("This is a error response \"%s\"", errResp.Error.Message)
		app.handleWebsocketErrorResponse(conn, errResp.Id, errors.New(errResp.Error.Message))
		return
	}

	var packet cmd.WebsocketAction
	err = json.Unmarshal(message, &packet)
	if err != nil {
		log.Printf("Unmarshal from %s \"%s\": %v", conn.Hello.Name, message, err)
		return
	}

	//log.Printf(" => using %v", packet.Data)
	switch a := packet.Data.(type) {
	case *cmd.WebsocketResponseData:
		app.handleWebsocketResponse(conn, packet, packet.RawData)
	case *cmd.WebsocketRegisterActionData:
		app.handleWebsocketRegister(conn, *a)
	case *cmd.WebsocketPingActionData:
		app.handleWebsocketPing(conn, *a)
	case *cmd.WebsocketUnregisterActionData:
		app.handleWebsocketUnregister(conn, *a)
	case *cmd.Hello:
		app.handleWebsocketAuth(conn, packet, *a)
	case *cmd.ForwardActionData:
		app.handleForwardAction(conn, packet, *a)
	//case *Hello:
	//	app.handleHelloAction(conn, packet, *a)

	default:
		log.Printf("Unrecognized websocket action '%s'", packet.Action)
	}
}

func (app *OvpnAdmin) handleWebsocketResponse(conn *rpi.WsSafeConn, packet cmd.WebsocketAction, data json.RawMessage) {
	_, wsConn := app.findConnection(conn)
	if wsConn == nil {
		log.Printf("Can't find connection")
		return
	}

	for i, req := range wsConn.RequestQueue {
		if req.Id == *packet.Id {
			wsConn.RequestQueue = append(wsConn.RequestQueue[0:i], wsConn.RequestQueue[i+1:]...)
			log.Printf("< handle response %d (%d bytes)", req.Id, len(data))
			req.Cb(data, nil)
			return
		}
	}
	log.Printf("Can't find pending request %d on %s (pending: %d)", *packet.Id, wsConn.RealAddress, len(wsConn.RequestQueue))
}

func (app *OvpnAdmin) handleWebsocketErrorResponse(conn *rpi.WsSafeConn, id int64, err error) {
	_, wsConn := app.findConnection(conn)
	if wsConn == nil {
		log.Printf("Can't find connection")
		return
	}

	for i, req := range wsConn.RequestQueue {
		if req.Id == id {
			wsConn.RequestQueue = append(wsConn.RequestQueue[0:i], wsConn.RequestQueue[i+1:]...)
			log.Printf("< handle error response %d", req.Id)
			req.Cb(nil, err)

			return
		}
	}
	log.Printf("Can't find pending request %d on %s (pending: %d)", id, wsConn.RealAddress, len(wsConn.RequestQueue))
}

func (app *OvpnAdmin) findConnection(conn *rpi.WsSafeConn) (*model.Device, *rpi.RpiConnection) {
	for _, device := range app.clients {
		for _, rpic := range device.Rpic {
			if rpic.Ws.Ws == conn.Ws {
				return device, rpic
			}
		}
	}
	return nil, nil
}

func (app *OvpnAdmin) handleForwardAction(conn *rpi.WsSafeConn, packet cmd.WebsocketAction, data cmd.ForwardActionData) {
	client := app.getDevice(data.Target)
	if client == nil {
		app.send(conn, cmd.WebsocketErrorResponse{Id: *packet.Id, Error: cmd.ErrorMessage{Message: "Can't find device"}})
		return
	}
	if len(client.Rpic) == 0 {
		app.send(conn, cmd.WebsocketErrorResponse{Id: *packet.Id, Error: cmd.ErrorMessage{Message: "RPiC not connected"}})
		return
	}
	rpic := client.Rpic[0]
	rpic.Request(data.Action, data.Data, func(response json.RawMessage, err error) {
		//log.Printf("got response from device: %d bytes", len(response))
		if err != nil {
			app.send(conn, cmd.WebsocketErrorResponse{Id: *packet.Id, Error: cmd.ErrorMessage{Message: err.Error()}})
		} else {
			log.Printf("success remote command to %s: %s", client.Username, data.Action)
			if data.Action == "request" {
				app.handleForwardedRequest(client, data.Data, response)
			}
			app.send(conn, cmd.WebsocketResponse{Id: packet.Id, RawData: response})
		}
	})
	//app.send(conn, WebsocketAction{Action: "pong", Data: data})
}

func (app *OvpnAdmin) handleForwardedRequest(client *model.Device, rawCmd json.RawMessage, response json.RawMessage) {
	//log.Printf("Parsing")
	var cmd RequestActionData
	err := json.Unmarshal(rawCmd, &cmd)
	if err != nil {
		log.Printf("Can't parse forwarded packet %v", err)
		return
	}
	if len(cmd.Command) == 0 {
		log.Printf("Not a command")
		return
	}
	log.Printf("handle %s", cmd.Command)
	if cmd.Command == "apt-install" {
		app.handleForwardedAptInstall(client, response)
	} else if cmd.Command == "apt-remove" {
		app.handleForwardedAptRemove(client, response)
	} else {
		log.Printf("Nothing to do with command %s", cmd.Command)
	}
}

func (app *OvpnAdmin) handleForwardedAptInstall(conn *model.Device, data json.RawMessage) {
	log.Printf("add package to %d ", len(conn.RpiState.InstalledPackages))
	log.Printf(" -> %v ", data)
}

func (app *OvpnAdmin) handleForwardedAptRemove(conn *model.Device, data json.RawMessage) {
	log.Printf("remove package from %d ", len(conn.RpiState.InstalledPackages))
	log.Printf(" -> %v ", data)
}

func (app *OvpnAdmin) handleWebsocketPing(conn *rpi.WsSafeConn, data cmd.WebsocketPingActionData) {
	log.Printf("respond to ping with %d", data.Time)
	app.send(conn, cmd.WebsocketAction{Action: "pong", Data: data})
}

func (app *OvpnAdmin) handleWebsocketRegister(conn *rpi.WsSafeConn, data cmd.WebsocketRegisterActionData) {
	streamName := fmt.Sprintf("%v", data.Stream)
	conn.Streams = append(conn.Streams, streamName)
}

func (app *OvpnAdmin) handleWebsocketUnregister(conn *rpi.WsSafeConn, data cmd.WebsocketUnregisterActionData) {
	streamName := fmt.Sprintf("%v", data.Stream)
	conn.Streams = removeString(conn.Streams, streamName)
}

func (app *OvpnAdmin) handleWebsocketAuth(conn *rpi.WsSafeConn, packet cmd.WebsocketAction, data cmd.Hello) {
	if conn.Ws == nil {
		return
	}
	//log.Errorf("Try to log as %s", data.Username)
	device := app.getDevice(data.Name)
	if device == nil {
		log.Printf("Can't find device %s\n", data.Name)
		app.send(conn, cmd.WebsocketAction{Action: "auth", Data: cmd.WebsocketAuthResponse{Status: "ko"}})
		return
	}
	log.Printf("Successfully logged for device %s\n", data.Name)
	//app.send(conn, WebsocketAction{Action: "auth", Data: WebsocketAuthResponse{Status: "ok"}})

	log.Printf("current time %d", time.Now().UnixMilli())
	log.Printf("rpic uptime %d", data.Uptime)
	data.Boot = time.Now().Add(time.Duration(-data.Uptime))

	conn.Role = "rpic"
	//conn.hello = data

	log.Printf("add rpic to connections %v", device)
	rpic := rpi.AddOrUpdateRpic(conn, &data)
	log.Printf("rpi connected '%s'\n", device.Username)
	device.Rpic = append(device.Rpic, rpic)
	log.Printf("sending signal to auto update thread %v", app.triggerUpdateChan)
	app.triggerUpdateChan <- device
	log.Printf("send response to request %d", packet.Id)
	app.send(conn, cmd.WebsocketAction{
		Id:   packet.Id,
		Data: cmd.WebsocketAuthResponse{Status: "ok"},
	})
	log.Printf("broadcast %s", "user.update."+device.Username+".rpic")
	app.broadcast(WebsocketPacket{Stream: "user.update." + device.Username, Data: device})
	app.broadcast(WebsocketPacket{Stream: "user.update." + device.Username + ".rpic", Data: device.Rpic})
}

func removeString(arr []string, search string) []string {
	newArr := make([]string, 0)
	for _, s := range arr {
		if s != search {
			newArr = append(newArr, s)
		}
	}
	return newArr
}

func next(conn *rpi.WsSafeConn) {
	//log.Printf("send keep alive after %d second", time.Now().Unix() - conn.last.Unix())
	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	conn.Last = time.Now()
	err := conn.Ws.WriteMessage(websocket.PingMessage, []byte("keepalive"))
	if err != nil {
		return
	}
	conn.Next = time.AfterFunc(time.Duration(30)*time.Second, func() {
		next(conn)
	})
}

func isRegistered(streamName string, conn *rpi.WsSafeConn) bool {
	for _, s := range conn.Streams {
		if s == streamName {
			return true
		}
	}
	return false
}

func (app *OvpnAdmin) broadcast(v WebsocketPacket) {
	for _, conn := range app.wsConnections {
		if isRegistered(v.Stream, conn) {
			app.send(conn, v)
		}
	}
}

func (app *OvpnAdmin) send(conn *rpi.WsSafeConn, v interface{}) {
	//log.Printf("send message after %d second", time.Now().Unix() - conn.last.Unix())
	if conn.Next != nil {
		conn.Next.Stop()
	}
	conn.Mu.Lock()
	defer conn.Mu.Unlock()
	conn.Last = time.Now()
	conn.Ws.WriteJSON(v)
	conn.Next = time.AfterFunc(time.Duration(30)*time.Second, func() {
		next(conn)
	})
}

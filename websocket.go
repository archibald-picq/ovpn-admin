package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"time"
)

type WebsocketPacket struct {
	Stream string      `json:"stream"`
	Data   interface{} `json:"data"`
}

type WebsocketAction struct {
	Id     *int64       `json:"id,omitempty"`
	Action string      `json:"action"`
	Data   interface{} `json:"-"`
	RawData json.RawMessage `json:"data"`
}

type WebsocketResponse struct {
	Id     *int64       `json:"id,omitempty"`
	Data   interface{} `json:"-"`
	RawData json.RawMessage `json:"data"`
}

type DecodedData struct {
}

type WebsocketResponseData struct {
	DecodedData
}

type ForwardActionData struct {
	Target string `json:"target"`
	Action string `json:"action"`
	Data   interface{} `json:"data"`
}


type Hello struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Uptime  int64  `json:"uptime"`
	Boot    time.Time `json:"boot"`
	Remote  string `json:"remote"`
	DecodedData
}

type WebsocketPingActionData struct {
	//Raw  string `json:"raw"`
	Time int64  `json:"time"`
	DecodedData
}
type WebsocketRegisterActionData struct {
	Stream string `json:"stream"`
	DecodedData
}

type WebsocketUnregisterActionData struct {
	Stream string `json:"stream"`
	DecodedData
}

type WebsocketAuthResponse struct {
	Status string `json:"status"`
	DecodedData
}

type WsErrorResponse struct {
	Id      *int64 `json:"id"`
	Message string `json:"message"`
}

func (app *OvpnAdmin) checkWebsocketOrigin(r *http.Request) bool {
	return true
}
func (app *OvpnAdmin) removeConnection(conn *websocket.Conn) {
	log.Printf("web client disconnected, removing connection %s", conn.RemoteAddr().String())
	conn.Close()
	var found *WsSafeConn
	for i, c := range app.wsConnections {
		if c.ws == conn {
			found = c;
			app.wsConnections = remove(app.wsConnections, i)
		}
	}
	if found == nil {
		log.Printf("Websocket client NOT found, can't remove from Rpic")
		return
	}
	log.Printf("Websocket client found for removal with role %s", found.role)
	if found.role == "rpic" {
		for _, client := range app.clients {
			for j, rpic := range client.Rpic {
				if rpic.ws.ws == found.ws {
					app.onRemoveRpi(client, client.Rpic[j])
					client.Rpic = removeRpi(client.Rpic, j)
					log.Printf("rpic disconnected, pool size: %r", len(client.Rpic))
					app.broadcast(WebsocketPacket{Stream: "user.update." + client.Username, Data: client})
					app.broadcast(WebsocketPacket{Stream: "user.update." + client.Username+".rpic", Data: client.Rpic})
					break
				}
			}
		}
		log.Printf("rpic disconnected")
	}
}

func remove(s []*WsSafeConn, i int) []*WsSafeConn {
	return append(s[0:i], s[i+1:]...)
	//s[i] = s[len(s)-1]
	//return s[:len(s)-1]
}
func removeRpi(s []*WsRpiConnection, i int) []*WsRpiConnection {
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
	wsSafe := new(WsSafeConn)
	wsSafe.ws = c
	wsSafe.last = time.Now()
	wsSafe.next = time.AfterFunc(time.Duration(30) * time.Second, func() {
		next(wsSafe)
	})
	wsSafe.xForwardedFor = xForwardedFor
	wsSafe.xForwardedProto = xForwardedProto
	wsSafe.userAgent = userAgent
	app.wsConnections = append(app.wsConnections, wsSafe)
	log.Printf("connected, pool size: %d", len(app.wsConnections))

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		wsSafe.last = time.Now()
		//switch messageType {
		//case websocket.TextMessage:
		//	log.Printf("recv (text): %s", bytes.TrimRight(message, "\n"))
		//case websocket.BinaryMessage:
		//	log.Printf("recv (binary): %s", message)
		//}
		app.handleWebsocketMessage(wsSafe, message)
	}
}

func (action WebsocketAction) MarshalJSON() ([]byte, error) {
	//log.Printf("marshal %v\n", action)
	type packet WebsocketAction
	if action.Data != nil {
		b, err := json.Marshal(action.Data)
		if err != nil {
			return nil, err
		}
		action.RawData = b
	}
	str, err := json.Marshal((packet)(action))
	//log.Printf("marshaled %v\n", str)

	return str, err
}

func (action *WebsocketAction) UnmarshalJSON(data []byte) error {
	type packet WebsocketAction
	if err := json.Unmarshal(data, (*packet)(action)); err != nil {
		return err
	}
	//log.Printf("parsing '%s'", action.Action)
	var i interface{}
	if len(action.Action) == 0 {
		i = &WebsocketResponseData{}
	} else {
		switch action.Action {
		case "ping":
			i = &WebsocketPingActionData{}
		case "auth":
			i = &Hello{}
		case "register":
			i = &WebsocketRegisterActionData{}
		case "unregister":
			i = &WebsocketUnregisterActionData{}
		case "forward":
			i = &ForwardActionData{}
		//case "hello":
		//	i = &Hello{}
		default:
			return errors.New("unknown action type")
		}
	}

	if err := json.Unmarshal(action.RawData, i); err != nil {
		return err
	}
	action.Data = i
	return nil
}
func (app *OvpnAdmin) handleWebsocketMessage(conn *WsSafeConn, message []byte) {
	var packet WebsocketAction

	err := json.Unmarshal(message, &packet)
	if err != nil {
		log.Printf("Unmarshal: %v", err)
		return
	}

	//log.Printf(" => using %v", packet.Data)
	switch a := packet.Data.(type) {
	case *WebsocketResponseData:
		app.handleWebsocketResponse(conn, packet, packet.RawData)
	case *WebsocketRegisterActionData:
		app.handleWebsocketRegister(conn, *a)
	case *WebsocketPingActionData:
		app.handleWebsocketPing(conn, *a)
	case *WebsocketUnregisterActionData:
		app.handleWebsocketUnregister(conn, *a)
	case *Hello:
		app.handleWebsocketAuth(conn, packet, *a)
	case *ForwardActionData:
		app.handleForwardAction(conn, packet, *a)
	//case *Hello:
	//	app.handleHelloAction(conn, packet, *a)

	default:
		log.Printf("Unrecognized websocket action '%s'", packet.Action)
	}
}

func (app *OvpnAdmin) handleWebsocketResponse(conn *WsSafeConn, packet WebsocketAction, data json.RawMessage) {
	_, wsConn := app.findConnection(conn)
	if wsConn == nil {
		log.Printf("Can't find connection")
		return
	}

	for i, req := range wsConn.requestQueue {
		if req.id == *packet.Id {
			wsConn.requestQueue = append(wsConn.requestQueue[0:i], wsConn.requestQueue[i+1:]...)
			req.cb(data)

			return
		}
	}
	log.Printf("Can't find pending request %d on %s (pending: %d)", *packet.Id, wsConn.RealAddress, len(wsConn.requestQueue))
}

func (app *OvpnAdmin) findConnection(conn *WsSafeConn) (*ClientCertificate, *WsRpiConnection) {
	for _, certificate := range app.clients {
		for _, rpic := range certificate.Rpic {
			if rpic.ws.ws == conn.ws {
				return certificate, rpic
			}
		}
	}
	return nil, nil
}

func (app *OvpnAdmin) handleForwardAction(conn *WsSafeConn, packet WebsocketAction, data ForwardActionData) {
	client := app.getCertificate(data.Target)
	if client == nil {
		app.send(conn, WsErrorResponse{packet.Id, "Can't find certificate"})
		return
	}
	if len(client.Rpic) == 0 {
		app.send(conn, WsErrorResponse{packet.Id, "RPiC not connected"})
		return
	}
	rpic := client.Rpic[0]
	rpic.request(data.Action, data.Data, func(response json.RawMessage) {
		log.Printf("got response from device: %d bytes", len(response))
		app.send(conn, WebsocketResponse{Id: packet.Id, RawData: response})
	})
	//app.send(conn, WebsocketAction{Action: "pong", Data: data})
}

func (app *OvpnAdmin) handleWebsocketPing(conn *WsSafeConn, data WebsocketPingActionData) {
	log.Printf("respond to ping with %d", data.Time)
	app.send(conn, WebsocketAction{Action: "pong", Data: data})
}

func (app *OvpnAdmin) handleWebsocketRegister(conn *WsSafeConn, data WebsocketRegisterActionData) {
	streamName := fmt.Sprintf("%v", data.Stream)
	conn.streams = append(conn.streams, streamName)
}

func (app *OvpnAdmin) handleWebsocketUnregister(conn *WsSafeConn, data WebsocketUnregisterActionData) {
	streamName := fmt.Sprintf("%v", data.Stream)
	conn.streams = removeString(conn.streams, streamName)
}

func (app *OvpnAdmin) handleWebsocketAuth(conn *WsSafeConn, packet WebsocketAction, data Hello) {
	if conn.ws == nil {
		return
	}
	//log.Errorf("Try to log as %s", data.Username)
	certificate := app.getCertificate(data.Name)
	if certificate == nil {
		log.Printf("Can't find certificate %s\n", data.Name)
		app.send(conn, WebsocketAction{Action: "auth", Data: WebsocketAuthResponse{Status: "ko"}})
		return
	}
	log.Printf("Successfully logged for certificate %s\n", data.Name)
	//app.send(conn, WebsocketAction{Action: "auth", Data: WebsocketAuthResponse{Status: "ok"}})

	log.Printf("current time %d", time.Now().UnixMilli())
	log.Printf("rpic uptime %d", data.Uptime)
	data.Boot = time.Now().Add(time.Duration(-data.Uptime))

	conn.role = "rpic"
	//conn.hello = data

	log.Printf("add rpic to connections %v", certificate)
	app.addOrUpdateRpic(certificate, conn, &data)
	log.Printf("send response to request %d", packet.Id)
	app.send(conn, WebsocketAction{
		Id: packet.Id,
		Data: WebsocketAuthResponse{Status: "ok"},
	})
	log.Printf("broadcast %s", "user.update." + certificate.Username+".rpic")
	app.broadcast(WebsocketPacket{Stream: "user.update." + certificate.Username, Data: certificate})
	app.broadcast(WebsocketPacket{Stream: "user.update." + certificate.Username+".rpic", Data: certificate.Rpic})
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

func next(conn *WsSafeConn) {
	//log.Printf("send keep alive after %d second", time.Now().Unix() - conn.last.Unix())
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.last = time.Now()
	err := conn.ws.WriteMessage(websocket.PingMessage, []byte("keepalive"))
	if err != nil {
		return
	}
	conn.next = time.AfterFunc(time.Duration(30) * time.Second, func() {
		next(conn)
	})
}

func isRegistered(streamName string, conn *WsSafeConn) bool {
	for _, s := range conn.streams {
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

func (app *OvpnAdmin) send(conn *WsSafeConn, v interface{}) {
	//log.Printf("send message after %d second", time.Now().Unix() - conn.last.Unix())
	if conn.next != nil {
		conn.next.Stop()
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.last = time.Now()
	conn.ws.WriteJSON(v)
	conn.next = time.AfterFunc(time.Duration(30) * time.Second, func() {
		next(conn)
	})
}

type Request struct {
	id int64
	cb func(response json.RawMessage)
}

type WsRpiConnection struct {
	RealAddress    string    `json:"realAddress"`
	Ssl            bool      `json:"ssl"`
	ConnectedSince time.Time `json:"connectedSince"`
	LastRef        time.Time `json:"lastRef"`

	Hello          *Hello    `json:"hello,omitempty"`
	UserAgent      *string   `json:"userAgent"`
	reqIndex       int64
	requestQueue   []Request
	ws             *WsSafeConn
}

func (conn *WsRpiConnection) request(action string, data interface{}, f func(response json.RawMessage)) {
	index := conn.reqIndex + 1
	conn.reqIndex++
	conn.requestQueue = append(conn.requestQueue, Request{index, f})
	log.Printf("queing request %d on %s (pending %d)", index, conn.RealAddress, len(conn.requestQueue))
	conn.ws.mu.Lock()
	defer conn.ws.mu.Unlock()
	err := conn.ws.ws.WriteJSON(WebsocketAction{&index, action, data, nil})
	if err != nil {
		log.Printf("Cant send packet %v", err)
		return
	}
}

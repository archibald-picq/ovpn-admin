package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"github.com/gorilla/websocket"
	"time"
	"golang.org/x/exp/slices"
)

type WebsocketPacket struct {
	Stream string      `json:"stream"`
	Data   interface{} `json:"data"`
}

type WebsocketAction struct {
	Action string      `json:"action"`
	Data   interface{} `json:"-"`
	RawData json.RawMessage `json:"data"`
}

type DecodedData struct {
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

type WebsocketAuthActionData struct {
	Username  string `json:"username"`
	DecodedData
}

type WebsocketAuthResponse struct {
	Status string `json:"status"`
	DecodedData
}

func (action WebsocketAction) MarshalJSON() ([]byte, error) {
	//log.Printf("marshal %s\n", action)
	type fleet WebsocketAction
	if action.Data != nil {
		b, err := json.Marshal(action.Data)
		if err != nil {
			return nil, err
		}
		action.RawData = b
	}
	return json.Marshal((fleet)(action))
}

func (action *WebsocketAction) UnmarshalJSON(data []byte) error {
	type packet WebsocketAction
	if err := json.Unmarshal(data, (*packet)(action)); err != nil {
		return err
	}
	var i interface{}
	switch action.Action {
	case "ping":
		i = &WebsocketPingActionData{}
	case "auth":
		i = &WebsocketAuthActionData{}
	case "register":
		i = &WebsocketRegisterActionData{}
	case "unregister":
		i = &WebsocketUnregisterActionData{}
	default:
		return errors.New("Unknown action type")
	}

	if err := json.Unmarshal(action.RawData, i); err != nil {
		return err
	}
	action.Data = i
	return nil
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
	log.Printf("Websocket client found with role %s", found.role)
	if found.role == "rpic" {
		for _, client := range app.clients {
			for j, rpic := range client.Rpic {
				if rpic.ws == found {
					client.Rpic = removeRpi(client.Rpic, j)
					log.Printf("rpic disconnected, pool size: %r", len(client.Rpic))
					app.broadcast(WebsocketPacket{Stream: "user.update." + client.Username, Data: client})
					return
				}
			}
		}
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
		messageType, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		wsSafe.last = time.Now()
		switch messageType {
		case websocket.TextMessage:
			log.Printf("recv (text): %s", bytes.TrimRight(message, "\n"))
		case websocket.BinaryMessage:
			log.Printf("recv (binary): %s", message)
		}
		app.handleWebsocketMessage(wsSafe, message)
	}
}

func (app *OvpnAdmin) handleWebsocketMessage(conn *WsSafeConn, message []byte) {
	var packet WebsocketAction

	err := json.Unmarshal(message, &packet)
	if err != nil {
		log.Print(err)
		return
	}
	switch a := packet.Data.(type) {
	case *WebsocketRegisterActionData:
		app.handleWebsocketRegister(conn, *a)
	case *WebsocketPingActionData:
		app.handleWebsocketPing(conn, *a)
	case *WebsocketUnregisterActionData:
		app.handleWebsocketUnregister(conn, *a)
	case *WebsocketAuthActionData:
		app.handleWebsocketAuth(conn, *a)
	default:
		log.Printf("Unrecognized websocket action %s", packet.Action)
	}
}

func (app *OvpnAdmin) handleWebsocketPing(conn *WsSafeConn, data WebsocketPingActionData) {
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
func (app *OvpnAdmin) handleWebsocketAuth(conn *WsSafeConn, data WebsocketAuthActionData) {
	//log.Errorf("Try to log as %s", data.Username)
	certificate := app.getCertificate(data.Username)
	if certificate == nil {
		log.Printf("Can't find certificate %s\n", data.Username)
		app.send(conn, WebsocketAction{Action: "auth", Data: WebsocketAuthResponse{Status: "ko"}})
		return
	}
	log.Printf("Successfully logged for certificate %s\n", data.Username)
	app.send(conn, WebsocketAction{Action: "auth", Data: WebsocketAuthResponse{Status: "ok"}})
	conn.role = "rpic"
	conn.username = data.Username

	app.addOrUpdateRpic(certificate, conn)
	app.broadcast(WebsocketPacket{Stream: "user.update." + certificate.Username, Data: certificate})
}

func removeString(s []string, search string) []string {
	i := slices.IndexFunc(s, func(c string) bool {return c == search})
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
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

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"github.com/gorilla/websocket"
	"time"
	"golang.org/x/exp/slices"

	log "github.com/sirupsen/logrus"
)

type WebsocketPacket struct {
	Stream string      `json:"stream"`
	Data   interface{} `json:"data"`
}

type WebsocketAction struct {
	Action string      `json:"action"`
	Data   interface{} `json:"data"`
}

func (oAdmin *OvpnAdmin) checkWebsocketOrigin(r *http.Request) bool {
	return true
}
func (oAdmin *OvpnAdmin) removeConnection(conn *websocket.Conn) {
	conn.Close()
	for i, c := range oAdmin.wsConnections {
		if c.ws == conn {
			oAdmin.wsConnections = remove(oAdmin.wsConnections, i)
		}
	}
	log.Printf("disconnected, pool size: %d", len(oAdmin.wsConnections))
}

func remove(s []*WsSafeConn, i int) []*WsSafeConn {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}
func (oAdmin *OvpnAdmin) websocket(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade error:", err)
		return
	}
	defer oAdmin.removeConnection(c)
	wsSafe := new(WsSafeConn)
	wsSafe.ws = c
	wsSafe.last = time.Now()
	wsSafe.next = time.AfterFunc(time.Duration(30) * time.Second, func() {
		next(wsSafe)
	})
	oAdmin.wsConnections = append(oAdmin.wsConnections, wsSafe)
	log.Printf("connected, pool size: %d", len(oAdmin.wsConnections))

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		wsSafe.last = time.Now()
		log.Printf("recv: %s (type: %v)", message, mt)
		oAdmin.handleWebsocketMessage(wsSafe, message)
	}
}

func (oAdmin *OvpnAdmin) handleWebsocketMessage(conn *WsSafeConn, message []byte) {
	var packet WebsocketAction

	err := json.Unmarshal(message, &packet)
	if err != nil {
		log.Errorln(err)
	}
	if packet.Action == "register" {
		streamName := fmt.Sprintf("%v", packet.Data)
		conn.streams = append(conn.streams, streamName)
	} else if packet.Action == "unregister" {
		streamName := fmt.Sprintf("%v", packet.Data)
		conn.streams = removeString(conn.streams, streamName)
	} else {
		log.Errorf("Unrecognized websocket action %s", packet.Action)
	}
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

func (oAdmin *OvpnAdmin) broadcast(v WebsocketPacket) {
	for _, conn := range oAdmin.wsConnections {
		if isRegistered(v.Stream, conn) {
			oAdmin.send(conn, v)
		}
	}
}

func (oAdmin *OvpnAdmin) send(conn *WsSafeConn, v interface{}) {
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

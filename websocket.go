package main

import (
	"net/http"
	"github.com/gorilla/websocket"
	"time"

	log "github.com/sirupsen/logrus"
)

type WebsocketPacket struct {
	Stream string      `json:"stream"`
	Data   interface{} `json:"data"`
}

func (oAdmin *OvpnAdmin) checkWebsocketOrigin(r *http.Request) bool {
	return true
}
func (oAdmin *OvpnAdmin) removeConnection(conn *websocket.Conn) {
	for i, c := range oAdmin.wsConnections {
		if c == conn {
			oAdmin.wsConnections = remove(oAdmin.wsConnections, i)
		}
	}
	log.Printf("disconnected, pool size: %d", len(oAdmin.wsConnections))
}

func remove(s []*websocket.Conn, i int) []*websocket.Conn {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}
func (oAdmin *OvpnAdmin) websocket(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()
	defer oAdmin.removeConnection(c)
	oAdmin.wsConnections = append(oAdmin.wsConnections, c)
	log.Printf("connected, pool size: %d", len(oAdmin.wsConnections))
	keepAlive(c, 30 * time.Second)
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		log.Printf("recv: %s", message)
		err = c.WriteMessage(mt, message)
		if err != nil {
			log.Println("write:", err)
			break
		}
	}
	log.Println("Disconnected")
}

func keepAlive(c *websocket.Conn, timeout time.Duration) {
	lastResponse := time.Now()
	c.SetPongHandler(func(msg string) error {
		lastResponse = time.Now()
		return nil
	})

	go func() {
		for {
			log.Printf("send keep alive")
			err := c.WriteMessage(websocket.PingMessage, []byte("keepalive"))
			if err != nil {
				return
			}
			time.Sleep(timeout)
			if time.Since(lastResponse) > timeout {
				c.Close()
				return
			}
		}
	}()
}

func (oAdmin *OvpnAdmin) broadcast(v interface{}) {
	for _, c := range oAdmin.wsConnections {
		c.WriteJSON(v)
	}
}

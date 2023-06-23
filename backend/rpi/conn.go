package rpi

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"rpiadm/backend/rpi/cmd"
	"sync"
	"time"
)

type WsSafeConn struct {
	Ws              *websocket.Conn
	Mu              sync.Mutex
	Last            time.Time
	Next            *time.Timer
	Streams         []string
	Role            string
	Hello           cmd.Hello
	XForwardedFor   string
	XForwardedProto string
	UserAgent       string
}

type Request struct {
	Id int64
	Cb func(response json.RawMessage, err error)
}

type WsRpiConnection struct {
	RealAddress    string    `json:"realAddress"`
	Ssl            bool      `json:"ssl"`
	ConnectedSince time.Time `json:"connectedSince"`
	LastRef        time.Time `json:"lastRef"`

	Hello        *cmd.Hello `json:"hello,omitempty"`
	UserAgent    *string    `json:"userAgent"`
	reqIndex     int64
	RequestQueue []Request
	Ws           *WsSafeConn `json:"-"`
}

func AddOrUpdateRpic(ws *WsSafeConn, hello *cmd.Hello) *WsRpiConnection {
	connection := WsRpiConnection{
		Ws: ws,
	}
	connection.RealAddress = connection.Ws.Ws.RemoteAddr().String()
	connection.ConnectedSince = time.Now()
	connection.LastRef = time.Now()
	if len(connection.Ws.XForwardedFor) > 0 {
		connection.RealAddress = connection.Ws.XForwardedFor
	}
	if connection.Ws.XForwardedProto == "https" {
		connection.Ssl = true
	}
	if len(connection.Ws.UserAgent) > 0 {
		connection.UserAgent = &connection.Ws.UserAgent
	}
	connection.Hello = hello
	return &connection
}

package rpi

import (
	"encoding/json"
	"log"
	"rpiadm/backend/rpi/cmd"
)

func (conn *RpiConnection) Request(action string, data interface{}, f func(response json.RawMessage, err error)) {
	index := conn.reqIndex + 1
	conn.reqIndex++
	conn.RequestQueue = append(conn.RequestQueue, Request{Id: index, Cb: f})
	log.Printf("> queing request %d on %s (pending %d)", index, conn.Hello.Name, len(conn.RequestQueue))
	conn.Ws.Mu.Lock()
	defer conn.Ws.Mu.Unlock()
	err := conn.Ws.Ws.WriteJSON(cmd.WebsocketAction{Id: &index, Action: action, Data: data})
	if err != nil {
		log.Printf("Cant send packet %v", err)
		return
	}
}

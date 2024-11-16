package connection

import (
	"encoding/json"
	"log"
	"rpiadm/backend/connection/request"
	"time"
)

type ConnectionInterface interface {
	WriteJSON(v interface{}) error
}

type ConnectCallback func()
type CommandCallback func(cmd string, data json.RawMessage) (interface{}, error)

type Connection struct {
	Name      string
	OnConnect ConnectCallback
	OnCommand CommandCallback
	Abs       ConnectionInterface
	//Base *Connection
	reqIndex     uint64
	requestQueue []request.Request
}

func (conn *Connection) WriteJSON(v interface{}) {
	conn.Abs.WriteJSON(v)
}

func (conn *Connection) handleRequest(req request.RequestAction, data request.RequestActionData) {
	//log.Printf("request %s (%s)", data.Command, data.RawData)

	output, err := conn.OnCommand(data.Command, data.RawData)
	if err != nil {
		resp := request.ResponseError{Id: req.Id, Error: request.ErrorMessage{Message: err.Error()}}
		conn.Abs.WriteJSON(&resp)
		return
	}

	response := request.Response{Id: req.Id, Data: output}
	conn.Abs.WriteJSON(&response)
}

func (conn *Connection) Request(action string, data interface{}, cb func(response json.RawMessage)) error {
	index := conn.reqIndex + 1
	conn.reqIndex++

	//log.Printf("queue expected response type %v", responseClass)
	// push cb for async resolve
	conn.requestQueue = append(conn.requestQueue, request.Request{
		Id: index,
		Cb: cb,
		//responseClass: responseClass,
	})
	err := conn.Abs.WriteJSON(request.RequestAction{
		Id:     &index,
		Action: &action,
		Data:   data,
	})
	if err != nil {
		return err
	}
	return nil
}

func (conn *Connection) DequeueRequest(id uint64, rawData json.RawMessage) error {
	req := conn.popRequest(id)
	if req == nil {
		log.Printf("Can't find request %d", id)
	}
	//log.Printf("Unmarshal %v into %v", rawData, req.responseClass)
	//if err := json.Unmarshal(rawData, &req.responseClass); err != nil {
	//	return err
	//}

	//log.Printf("Unmarshaled %v", req.responseClass)
	req.Cb(rawData)
	return nil
}

func (conn *Connection) popRequest(id uint64) *request.Request {
	for i, req := range conn.requestQueue {
		if req.Id == id {
			conn.requestQueue = append(conn.requestQueue[0:i], conn.requestQueue[i+1:]...)
			return &req
		}
	}
	return nil
}

func (conn *Connection) handleBinaryMessage(message []byte) {
	var packet request.RequestAction

	//fmt.Printf("decode %s\n", string(message))
	err := json.Unmarshal(message, &packet)
	if err != nil {
		log.Printf("Error decoding message: %s\n", err.Error())
		//conn.WriteJSON(request.Response{Id: req.Id, Error: &error})
		return
	}
	conn.onMessage(packet)
}

func (conn *Connection) onMessage(req request.RequestAction) {

	if req.Id != nil && (req.Action == nil || len(*req.Action) == 0) {
		conn.DequeueRequest(*req.Id, req.RawData)
		return
	}

	switch a := req.Data.(type) {
	case *request.MessagePingData:
		conn.decodePong(*a)
	case *request.RequestActionData:
		conn.handleRequest(req, *a)
	case *request.BluetoothActionData:
		conn.replyBluetoothMessage(*a)

	default:
		error := "Invalid action"
		conn.WriteJSON(request.Response{Id: req.Id, Error: &error})
	}

	//if resp.Data != nil || resp.Error != nil || resp.Id != nil {
	//
	//}
}

func (conn *Connection) decodePong(data request.MessagePingData) {
	//MessagePingData
	diff := time.Now().UnixMilli() - data.Time
	log.Printf("latency %d ms\n", diff)
}

func (conn *Connection) handleAuthResponse(data request.AuthResponseData) *request.ResponseData {
	log.Printf("auth returns '%s'", data.Status)
	if data.Status == "ok" {
		log.Printf("Auth OK\n")
	} else {
		log.Printf("Auth failed\n")
	}
	return nil
}

func (conn *Connection) sendPingAction(t time.Time) {
	//actionName := "ping"
	//err := conn.WriteJSON(RequestAction{
	//	Action: &actionName,
	//	Data:   MessagePingData{Time: t.UnixMilli()},
	//})
	//if err != nil {
	//	log.Println("write failed:", err)
	//	return
	//}
}

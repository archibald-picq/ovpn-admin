package request

import (
	"encoding/json"
	"errors"
)

type DecodedData struct {
}

type RequestAction struct {
	Id      *uint64         `json:"id,omitempty"`
	Action  *string         `json:"action,omitempty"`
	Data    interface{}     `json:"-"`
	RawData json.RawMessage `json:"data"`
}

type Response struct {
	Id      *uint64         `json:"id,omitempty"`
	Data    interface{}     `json:"-"`
	RawData json.RawMessage `json:"data,omitempty"`
	Error   *string         `json:"error,omitempty"`
}

type ErrorMessage struct {
	Message string `json:"message"`
}
type ResponseError struct {
	Id    *uint64      `json:"id"`
	Error ErrorMessage `json:"error,omitempty"`
}

type ResponseData struct {
}

type Request struct {
	Id uint64
	Cb func(response json.RawMessage)
}

type RequestActionData struct {
	Command string          `json:"command"`
	RawData json.RawMessage `json:"data"`
}

type ResponseActionData struct {
	Output interface{} `json:"output"`
	ResponseData
}

type MessagePingData struct {
	//Raw  string `json:"raw"`
	Time int64 `json:"time"`
	DecodedData
}

type AuthResponseData struct {
	Status string `json:"status"`
	ResponseData
}

func (action Response) MarshalJSON() ([]byte, error) {
	//log.Printf("marshal %s\n", action)
	type fleet Response
	if action.Data != nil {
		b, err := json.Marshal(action.Data)
		if err != nil {
			return nil, err
		}
		action.RawData = b
	}
	return json.Marshal((fleet)(action))
}

func (action RequestAction) MarshalJSON() ([]byte, error) {
	//log.Printf("marshal %s\n", action)
	type fleet RequestAction
	if action.Data != nil {
		b, err := json.Marshal(action.Data)
		if err != nil {
			return nil, err
		}
		action.RawData = b
	}
	return json.Marshal((fleet)(action))
}

func (action *RequestAction) UnmarshalJSON(data []byte) error {
	type packet RequestAction
	//log.Printf("recv: %s", data)
	if err := json.Unmarshal(data, (*packet)(action)); err != nil {
		return err
	}
	var i interface{}
	actionName := (*action).Action
	actionId := (*action).Id

	if (actionName == nil || len(*actionName) == 0) && actionId != nil {
		//log.Printf("nothing to do on unmarshall ...")
		i = &ResponseData{}
	} else {
		switch *action.Action {
		case "pong":
			i = &MessagePingData{}
		case "auth":
			i = &AuthResponseData{}
		case "request":
			i = &RequestActionData{}
		case "ping":
			i = &BluetoothActionData{}
		default:
			errors.New("unknown action type '" + *action.Action + "'")
		}
	}

	if err := json.Unmarshal(action.RawData, i); err != nil {
		return err
	}
	action.Data = i
	return nil
}

type BluetoothActionData struct {
	Method string `json:"method"`
	Url    string `json:"url"`
	Body   string `json:"body"`
}

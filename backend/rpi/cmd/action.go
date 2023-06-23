package cmd

import (
	"encoding/json"
	"errors"
	"log"
)

type DecodedData struct {
}

type ErrorMessage struct {
	Message string `json:"message"`
}

type WebsocketErrorResponse struct {
	Id    int64        `json:"id"`
	Error ErrorMessage `json:"error"`
}

type WebsocketAction struct {
	Id      *int64          `json:"id,omitempty"`
	Action  string          `json:"action"`
	Data    interface{}     `json:"-"`
	RawData json.RawMessage `json:"data"`
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
	//log.Printf("parsing '%v'", action)
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
			log.Printf("returns unknown action type")
			return errors.New("unknown action type")
		}
	}

	if err := json.Unmarshal(action.RawData, i); err != nil {
		return err
	}
	action.Data = i
	return nil
}

type WebsocketResponse struct {
	Id      *int64          `json:"id,omitempty"`
	Data    interface{}     `json:"-"`
	RawData json.RawMessage `json:"data"`
}

type WebsocketResponseData struct {
	DecodedData
}

type ForwardActionData struct {
	Target string          `json:"target"`
	Action string          `json:"action"`
	Data   json.RawMessage `json:"data"`
}

type WebsocketPingActionData struct {
	//Raw  string `json:"raw"`
	Time int64 `json:"time"`
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

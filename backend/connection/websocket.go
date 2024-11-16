package connection

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"log"
	"net/url"
	"time"
)

type WsConnection struct {
	name       string
	Url        *url.URL
	fullBuffer []byte
	conn       *websocket.Conn
	Base       *Connection
	CloseChan  chan interface{}
	ConnectionInterface
}

func (conn *WsConnection) tryConnect() error {
	log.Printf("Try connecting to %s", conn.Url.String())
	c, _, err := websocket.DefaultDialer.Dial(conn.Url.String(), nil)
	if err != nil {
		log.Printf("dial:", err)
		return err
		//conn.tryConnect()
	}

	conn.conn = c
	return nil
}

func (conn *WsConnection) Connect() error {
	log.Printf("in WsConnection::connect() with base: %v", conn.Url)

	currentUrl := conn.Url

	retry := 0
	for {
		err := conn.tryConnect()
		//if retry >= 5 {
		//	return err
		//}
		if err != nil {
			retry++
			time.Sleep(5 * time.Second)
		} else {
			log.Printf("Try connected succeed to %s", conn.Url.String())
			break
		}
	}
	defer func() {
		conn.conn.Close()
		close(conn.CloseChan)
		log.Printf("exit Connect() tread")
	}()
	//log.Printf("writing conn %v on %v", conn.conn, conn)
	//log.Printf("onConnect in this: %v, base: %v", conn, conn.base)
	conn.Base.OnConnect()

	readError := make(chan struct{})
	conn.CloseChan = make(chan interface{})

	go func() {
		defer close(readError)
		for {
			_, message, err := conn.conn.ReadMessage()
			if err != nil {
				log.Println("Error reading:", err)
				break
			}
			//log.Printf("recv: %s", message)
			conn.Base.handleBinaryMessage(message)
		}
		log.Printf("exit read thread")
	}()

	//ticker := time.NewTicker(time.Second * 5)
	//defer ticker.Stop()

	for {
		log.Println("waiting for readError or CloseChan")
		select {
		case <-readError:
			if currentUrl != nil {
				log.Printf("readError ... reconnect to %v -> %v\n", currentUrl, conn.Url)
				time.Sleep(5 * time.Second)
				err := conn.Connect()
				if err != nil {
					return err
				}
			} else {
				log.Println("readError, will change server")
				return nil
			}
		//case t := <-ticker.C:
		//	//log.Println("write:", t.String())
		//	conn.Base.sendPingAction(t)

		case i := <-conn.CloseChan:
			log.Printf("interrupt %v\n", i)

			currentUrl = nil
			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := conn.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
			}
			return nil
		}
	}
}
func (conn *WsConnection) Close() {
	if conn.conn != nil {
		log.Printf("closing real connection %v\n", conn)
		conn.CloseChan <- new(interface{})
		//conn.conn.Close()
	} else {
		log.Println("not connected yet")
	}
}

func (conn *WsConnection) WriteJSON(v interface{}) error {
	//log.Printf("WriteJSON in websocket with %v - conn: %v", conn, conn.conn)
	w, err := conn.conn.NextWriter(websocket.TextMessage)
	if err != nil {
		return err
	}
	err1 := json.NewEncoder(w).Encode(v)
	err2 := w.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

//func (conn *Connection) handleWebsocketMessage(message []byte) {
//	var packet WebsocketAction
//
//	err := json.Unmarshal(message, &packet)
//	if err != nil {
//		log.Println(err)
//	}
//	switch a := packet.Data.(type) {
//
//	default:
//		log.Printf("Unrecognized websocket action %s\n", packet.Action)
//	}
//}

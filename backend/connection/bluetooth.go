package connection

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"rpiadm/backend/connection/request"
	"tinygo.org/x/bluetooth"
)

var (
	serviceUUID = [16]byte{0x00, 0x00, 0xff, 0xe0, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb}
	rxUUID      = bluetooth.CharacteristicUUIDUARTRX // [16]byte{0x00, 0x00, 0xff, 0xe1, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb}
	txUUID      = bluetooth.CharacteristicUUIDUARTTX
)

var prefixName = "RPiC"

var adapter = bluetooth.DefaultAdapter

type BleConnection struct {
	name       string
	fullBuffer []byte
	rxChar     bluetooth.Characteristic
	txChar     bluetooth.Characteristic
	Base       *Connection
	ConnectionInterface
}

func (conn *Connection) replyBluetoothMessage(message request.BluetoothActionData) {

	log.Printf("method %s, url: %s", message.Method, message.Url)

	conn.WriteJSON(request.Response{Data: new(request.ResponseData)})
}

func (conn *BleConnection) Connect() error {
	log.Printf("check if BLE adapter is enabled ?")
	err := adapter.Enable()
	log.Printf(" -> check returns %v", err)
	if err != nil {
		//log.Printf("Can't start bluetooth")
		return err
	}

	adapter.SetConnectHandler(func(device bluetooth.Device, c bool) {
		if c {
			log.Printf("connect event...")
			conn.Base.OnConnect()
		} else {
			log.Printf("disconnect event...")
		}
	})

	adapter.AddService(&bluetooth.Service{
		UUID: bluetooth.NewUUID(serviceUUID),
		Characteristics: []bluetooth.CharacteristicConfig{
			{
				Handle: &conn.rxChar,
				UUID:   rxUUID,
				Flags:  bluetooth.CharacteristicWriteWithoutResponsePermission | bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicNotifyPermission | bluetooth.CharacteristicReadPermission,
				WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
					conn.fullBuffer = append(conn.fullBuffer, value...)
					conn.processBuffer()
				},
			},
			{
				Handle: &conn.txChar,
				UUID:   txUUID,
				Flags:  bluetooth.CharacteristicWriteWithoutResponsePermission | bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicNotifyPermission | bluetooth.CharacteristicReadPermission,
			},
		},
	})

	log.Printf("BLE configured")
	return nil
}

func (conn *BleConnection) UpdateAdvertiseName(name string) {
	bleName := prefixName
	if len(name) != 0 {
		bleName = bleName + "-" + name
	}

	adv := adapter.DefaultAdvertisement()
	err := adv.Configure(bluetooth.AdvertisementOptions{
		LocalName: bleName,
	})
	if err != nil {
		log.Printf("Fail to configure BLE advertisement %s", err)
		return
	}

	// Start advertising
	adv.Start()
	log.Printf("advertising as %s ...\n", bleName)
}

func (conn *BleConnection) processBuffer() {
	if len(conn.fullBuffer) < 1 {
		return
	}
	cmd := conn.fullBuffer[0]
	//log.Printf("recv: %v", conn.fullBuffer)

	if cmd == 0x42 {
		if len(conn.fullBuffer) < 5 {
			return
		}

		size := int(binary.BigEndian.Uint32(conn.fullBuffer[1:5]))

		if len(conn.fullBuffer) < 5+size {
			//log.Printf("not enought data yet (expect %d, got %d)", 5+size, len(conn.fullBuffer))
			return
		}
		payload := conn.fullBuffer[5 : 5+size]
		conn.fullBuffer = conn.fullBuffer[5+size:]
		conn.Base.handleBinaryMessage(payload)
	} else {
		log.Printf("Invalid command %d", cmd)
	}
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
func (conn *BleConnection) WriteJSON(v interface{}) error {
	str, err := json.Marshal(v)
	if err != nil {
		log.Printf("Cant serialize response %s", err)
		return err
	}
	//log.Printf("returns %s (length: %d)", string(str), len(str))
	bs := make([]byte, 1)
	bs[0] = 0x42
	bs = binary.BigEndian.AppendUint32(bs, uint32(len(str)))
	str = append(bs, str...)
	for len(str) > 0 {
		maxBytes := min(len(str), 512)
		toWrite := str[0:maxBytes]
		//log.Printf("writing %d\n", len(toWrite))
		written, err := conn.txChar.Write(toWrite)
		//log.Printf("written %d\n", written)
		str = str[written:]
		if err != nil {
			log.Printf("Cant write to characteristic %s", err.Error())
			return err
		}
	}

	return nil
}

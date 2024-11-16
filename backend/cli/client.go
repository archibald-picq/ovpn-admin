package cli

import (
	"github.com/mdp/qrterminal/v3"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func reader(r io.Reader) {
	var rawData = ""
	buf := make([]byte, 512)
	for {
		nr, err := r.Read(buf[:])
		if err != nil {
			return
		}
		data := buf[0:nr]
		rawData = rawData + string(data)
		lf := strings.Index(rawData, "\n")
		if lf != -1 {
			line := rawData[0:lf]
			rawData = rawData[lf+1:]
			log.Printf("Client got: '%s'\n", line)
		}
	}
}

var defaultCmd = "{\"command\":\"hi\"}"

func ConnectEchoSocket(cmd *string) {
	if cmd == nil {
		cmd = &defaultCmd
	}
	if *cmd == "{\"command\":\"qr\"}" {
		config := qrterminal.Config{
			Level:     qrterminal.M,
			Writer:    os.Stdout,
			BlackChar: qrterminal.BLACK,
			WhiteChar: qrterminal.WHITE,
			QuietZone: 2,
		}
		qrterminal.GenerateWithConfig("https://bus.picq.fr/device/", config)
		return
	}

	log.Printf("executing command '%s'", *cmd)
	c, err := net.Dial("unix", SOCKET_URL)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	go reader(c)
	for {
		_, err := c.Write([]byte(*cmd + "\n"))
		if err != nil {
			log.Fatal("write error:", err)
			break
		}
		time.Sleep(1e9)
	}
}

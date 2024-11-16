package cli

import (
	"log"
	"net"
	"os"
	"strings"
)

func echoServer(c net.Conn) {
	var rawData = ""
	buf := make([]byte, 512)
	for {
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]
		rawData = rawData + string(data)
		lf := strings.Index(rawData, "\n")
		if lf != -1 {
			line := rawData[0:lf]
			rawData = rawData[lf+1:]
			log.Printf("Server got: '%s'\n", line)
			_, err = c.Write([]byte(line + "\n"))
			if err != nil {
				log.Fatal("Write: ", err)
			}
		}
	}
}

func BindEchoSocket() {
	if _, err := os.Stat(SOCKET_URL); err == nil {
		c, err := net.Dial("unix", SOCKET_URL)
		if err != nil {
			os.Remove(SOCKET_URL)
		} else {
			c.Close()
			log.Fatal("Daemon already running on that socket")
		}
	}

	l, err := net.Listen("unix", SOCKET_URL)
	if err != nil {
		log.Fatal("listen error:", err)
	}

	for {
		fd, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}

		go echoServer(fd)
	}
}

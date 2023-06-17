package main

import (
	"encoding/json"
	"log"
	"time"
)


type LsbInfo struct {
	PrettyName      string `json:"prettyName"`
	Name            string `json:"name"`
	VersionId       int    `json:"versionId"`
	Version         string `json:"version"`
	VersionCodename string `json:"versionCodename"`
	Id              string `json:"id"`
	IdLike          string `json:"idLike"`
	HomeUrl         string `json:"homeUrl"`
	SupportUrl      string `json:"supportUrl"`
	BugReportUrl    string `json:"bugReportUrl"`
}

type Dpkg struct {
	Version      string `json:"version"`
	Lsb          *LsbInfo `json:"lsb,omitempty"`
	Packages     []InstalledPackage `json:"packages"`
}

type InstalledPackage struct {
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	Arch         string  `json:"arch"`
	Description  string  `json:"description"`
	DesiredState string  `json:"desiredState"`
	State        string  `json:"state"`
	Error        *string `json:"error,omitempty"`
}

type RpiState struct {
	Lsb *LsbInfo `json:"lsb,omitempty"`
	InstalledPackages []InstalledPackage
	installedPackagesLastCheck time.Time
}

type RequestActionData struct {
	Command string          `json:"command"`
	RawData json.RawMessage `json:"data,omitempty"`
	Data    interface{}     `json:"-"`
}

func (app *OvpnAdmin) addOrUpdateRpic(user *ClientCertificate, ws *WsSafeConn, hello *Hello) {
	connection := WsRpiConnection{
		ws: ws,
	}
	connection.RealAddress = connection.ws.ws.RemoteAddr().String()
	connection.ConnectedSince = time.Now()
	connection.LastRef = time.Now()
	if len(connection.ws.xForwardedFor) > 0 {
		connection.RealAddress = connection.ws.xForwardedFor
	}
	if connection.ws.xForwardedProto == "https" {
		connection.Ssl = true
	}
	if len(connection.ws.userAgent) > 0 {
		connection.UserAgent = &connection.ws.userAgent
	}
	connection.Hello = hello
	user.Rpic = append(user.Rpic, &connection)
	log.Printf("sending signal to auto update thread %v", app.triggerUpdateChan)
	app.triggerUpdateChan <- user
	log.Printf("rpi connected '%s'\n", user.Username)
}

func (app *OvpnAdmin) onRemoveRpi(user *ClientCertificate, rpic *WsRpiConnection) {
	app.triggerUpdateChan <- user
}

func (app *OvpnAdmin) autoUpdate() {
	log.Printf("binding.triggerUpdateChan %v", app.triggerUpdateChan)
	//ticker := time.NewTicker(time.Second * 5)
	//defer ticker.Stop()
	//for c := range app.triggerUpdateChan {
	//	app.updateState(c)
	//}
	intervalCheck := 1 * time.Minute
	var nextTickTimer *time.Timer
	for {
		select {
		case c := <-app.triggerUpdateChan:
			if c != nil {
				//log.Printf("update stat for specific device %s", c.Username)
				app.updateState(intervalCheck, c)
			} else {
				//log.Printf("update stat for all devices")
				for _, client := range app.clients {
					app.updateState(intervalCheck, client)
				}
			}

		//case t := <-ticker.C:
		//	log.Println("tick:", t.String())
			//conn.Base.sendPingAction(t)
			nextTick := app.calcNextTick(intervalCheck)
			log.Printf("next tick in %f", nextTick.Seconds())
			if nextTickTimer != nil {
				nextTickTimer.Reset(nextTick)
			} else {
				nextTickTimer = time.AfterFunc(nextTick, func() {
					//log.Printf("---- tick ----")
					//triggerUpdateChan <- user
					app.triggerUpdateChan <- nil
				})
			}
		}
	}
	//log.Printf("autoUpdate stopped")
}

func (app *OvpnAdmin) calcNextTick(intervalCheck time.Duration) time.Duration {
	nextTick := time.Duration(1 * time.Hour)
	now := time.Now()
	//log.Printf("next tick across %d clients", len(app.clients))
	for _, client := range app.clients {
		if len(client.Rpic) == 0 {
			continue
		}
		if client.RpiState == nil {
			log.Printf(" - client %s, no state yet\n", client.Username)
			return time.Duration(1 * time.Second)
		} else {
			lastCheck := client.RpiState.installedPackagesLastCheck
			expireAt := lastCheck.Add(intervalCheck).Sub(now)
			//log.Printf(" - client %s, exires in %f seconds\n", client.Username, expireAt.Seconds())
			if now.After(lastCheck.Add(expireAt)) {
				log.Printf(" - client %s, exired %f seconds ago\n", client.Username, now.Sub(lastCheck.Add(expireAt)).Seconds())
				return time.Duration(1 * time.Second)
			}
			//log.Printf("   - next in %f", expireAt.Seconds())
			if expireAt < nextTick {
				nextTick = expireAt
			}
		}

	}
	return nextTick
}

func (app *OvpnAdmin) updateState(intervalCheck time.Duration, user *ClientCertificate) {
	if len(user.Rpic) == 0 {
		return
	}
	rpic := user.Rpic[0]
	//log.Printf("check if %s as updated", user.Username)
	if user.RpiState == nil {
		user.RpiState = new(RpiState)
	}

	//log.Printf("last packages check %v", user.RpiState)
	now := time.Now()
	expired := now.Add(-intervalCheck)
	if user.RpiState.installedPackagesLastCheck.After(expired) {
		return
	}
	//log.Printf("Need to update packages")
	finished := make(chan bool)
	rpic.request("request", RequestActionData{Command: "dpkg"}, func(response json.RawMessage) {
		app.updatePackages(user, response)
		user.RpiState.installedPackagesLastCheck = now
		finished <- true
	})

	<- finished
	//if await {
	//	log.Printf("updateState finished with success")
	//} else {
	//	log.Printf("updateState finished with error")
	//}
}

func (app *OvpnAdmin) updatePackages(user *ClientCertificate, response json.RawMessage) {
	var packet Dpkg
	err := json.Unmarshal(response, &packet)
	if err != nil {
		log.Printf("Unmarshal: %v", err)
		return
	}
	//log.Printf("response %v", response)
	user.RpiState.Lsb = packet.Lsb
	user.RpiState.InstalledPackages = packet.Packages
	log.Printf("client %s: %d installed packages", user.Username, len(user.RpiState.InstalledPackages))
}

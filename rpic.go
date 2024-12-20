package main

import (
	"encoding/json"
	"log"
	"rpiadm/backend/model"
	"rpiadm/backend/rpi"
	"time"
)

type RequestActionData struct {
	Command string          `json:"command"`
	RawData json.RawMessage `json:"data,omitempty"`
	Data    interface{}     `json:"-"`
}

func (app *OvpnAdmin) onRemoveRpi(user *model.Device, rpic *rpi.RpiConnection) {
	app.triggerUpdateChan <- user
}

func (app *OvpnAdmin) autoUpdate() {
	//log.Printf("binding.triggerUpdateChan %v", app.triggerUpdateChan)
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
				//log.Printf("update stat for specific device %s", c.CommonName)
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
			//log.Printf("next tick in %f", nextTick.Seconds())
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
			lastCheck := client.RpiState.InstalledPackagesLastCheck
			expireAt := lastCheck.Add(intervalCheck).Sub(now)
			nextCheck := time.Now().Add(intervalCheck).Sub(now)
			//if expireAt < nextCheck {
			//	nextCheck = expireAt
			//}
			//log.Printf(" - client %s, exires in %f seconds\n", client.CommonName, expireAt.Seconds())
			if now.After(lastCheck.Add(expireAt)) {
				log.Printf(" - client %s, expired %f seconds ago\n", client.Username, now.Sub(lastCheck.Add(expireAt)).Seconds())
				return time.Duration(1 * time.Second)
			}
			//log.Printf("   - next in %f", expireAt.Seconds())
			if nextCheck < nextTick {
				nextTick = nextCheck
			}
		}

	}
	return nextTick
}

func (app *OvpnAdmin) updateState(intervalCheck time.Duration, user *model.Device) {
	if len(user.Rpic) == 0 {
		return
	}
	rpic := user.Rpic[0]
	//log.Printf("check if %s as updated", user.CommonName)
	if user.RpiState == nil {
		user.RpiState = new(rpi.RpiState)
	}

	//log.Printf("last packages check %v", user.RpiState)
	now := time.Now()
	expired := now.Add(-intervalCheck)
	if user.RpiState.InstalledPackagesLastCheck.After(expired) {
		return
	}
	//log.Printf("Need to update packages")
	finished := make(chan bool)
	rpic.Request("request", RequestActionData{Command: "dpkg"}, func(response json.RawMessage, err error) {
		app.updatePackages(user, response)
		user.RpiState.InstalledPackagesLastCheck = now
		finished <- true
	})

	<-finished
	//if await {
	//	log.Printf("updateState finished with success")
	//} else {
	//	log.Printf("updateState finished with error")
	//}
}

func (app *OvpnAdmin) updatePackages(user *model.Device, response json.RawMessage) {
	var packet rpi.Dpkg
	err := json.Unmarshal(response, &packet)
	if err != nil {
		log.Printf("Unmarshal: %v", err)
		return
	}
	//log.Printf("response %v", response)
	user.RpiState.Lsb = packet.Lsb
	user.RpiState.InstalledPackages = packet.Packages
	//log.Printf("client %s: %d installed packages", user.Username, len(user.RpiState.InstalledPackages))
}

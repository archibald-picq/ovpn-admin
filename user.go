package main

import (
	"encoding/json"
	"net/http"
)

func (app *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	app.usersList()
	usersList, _ := json.Marshal(app.clients)
	_, _ = w.Write(usersList)
	//fmt.Fprintf(w, "%s", usersList)
}

//func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
//	log.Info(r.RemoteAddr, " ", r.RequestURI)
//	enableCors(&w, r)
//	if (*r).Method == "OPTIONS" {
//		return
//	}
//	auth := getAuthCookie(r)
//	if hasReadRole := oAdmin.jwtHasReadRole(auth); !hasReadRole {
//		w.WriteHeader(http.StatusForbidden)
//		return
//	}
//	_ = r.ParseForm()
//	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
//	fmt.Fprintf(w, "%s", userStatistic)
//}

func (app *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	//log.Info(r.RemoteAddr, " ", r.RequestURI)
	enableCors(&w, r)
	if (*r).Method == "OPTIONS" {
		return
	}
	auth := getAuthCookie(r)
	if hasReadRole := app.jwtHasReadRole(auth); !hasReadRole {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	if *authByPassword {
		passwordChanged, passwordChangeMessage := app.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		if passwordChanged {
			w.WriteHeader(http.StatusOK)
			jsonRaw, _ := json.Marshal(MessagePayload{passwordChangeMessage})
			w.Write(jsonRaw)
			return
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			jsonRaw, _ := json.Marshal(MessagePayload{passwordChangeMessage})
			w.Write(jsonRaw)
			return
		}
	} else {
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}


//func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
//	log.Info(r.RemoteAddr, " ", r.RequestURI)
//	enableCors(&w, r)
//	if (*r).Method == "OPTIONS" {
//		return
//	}
//	_ = r.ParseForm()
//	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
//	fmt.Fprintf(w, "%s", r.FormValue("username"))
//}

package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
	log "github.com/sirupsen/logrus"
)

func jwtUsername(auth string) (bool, string) {
	if len(auth) <= 0 {
		return false, ""
	}
	token, err := jwt.Parse(auth, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(fRead(*jwtSecretFile)), nil
	})

	if err != nil {
		fmt.Println("token invalid")
		return false, ""
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		fmt.Println("token invalid")
		return false, ""
	}
	subject, ok := claims["sub"].(string)
	if !ok {
		fmt.Println("invalid subject")
		return false, ""
	}
	return true, subject
}

func jwtHasReadRole(auth string) bool {
	if len(auth) <= 0 {
		return false
	}
	token, err := jwt.Parse(auth, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(fRead(*jwtSecretFile)), nil
	})

	if err != nil {
		fmt.Println("token invalid")
		return false
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		fmt.Println("token invalid")
		return false
	}

	//fmt.Printf("Roles %v\n", claims["roles"])
	roles, ok := claims["roles"].(map[string]interface{})
	if !ok {
		// Can't assert, handle error.
		fmt.Println("invalid roles")
		return false
	}

	openvpn, ok := roles["openvpn"].(bool)
	if !ok {
		// Can't assert, handle error.
		fmt.Println("invalid roles type")
		return false
	}
	if openvpn {
		return true
	}
	return false
}


func (oAdmin *OvpnAdmin) authenticate(w http.ResponseWriter, r *http.Request) {
	auth := getAuthCookie(r)
	ok, _ := jwtUsername(auth)
	if ok {
		fmt.Fprintf(w, `{"message":"Already authenticated" }`)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var authPayload AuthenticatePayload
	err := json.NewDecoder(r.Body).Decode(&authPayload)
	if err != nil {
		log.Errorln(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, err := oAdmin.getEncryptedPasswordForUser(authPayload.Username)
	if err != nil {
		log.Errorln(err)
		w.WriteHeader(http.StatusForbidden)
	}

	err = bcrypt.CompareHashAndPassword([]byte(expectedPassword), []byte(authPayload.Password))
	if err != nil {
		fmt.Fprintf(w, `{"message":"Username or password does not match" }`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}


	expirationTime := time.Now().Add(24 * time.Hour)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		StandardClaims: jwt.StandardClaims{
			Subject:   authPayload.Username,
			ExpiresAt: expirationTime.Unix(),
		},
		Roles: Roles{
			Openvpn: true,
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString([]byte(fRead(*jwtSecretFile)))
	if err != nil {
		log.Errorln(err)
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "auth",
		Value:   tokenString,
		Expires: expirationTime,
	})
	rawJson, _ := json.Marshal(oAdmin.getUserProfile(authPayload.Username))
	_, err = w.Write(rawJson)
	if err != nil {
		log.Errorln("Fail to write response")
		return
	}
}

func (oAdmin *OvpnAdmin) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "auth",
		Value:   "",
		Expires: time.Now(),
	})
	w.WriteHeader(http.StatusNoContent)
}

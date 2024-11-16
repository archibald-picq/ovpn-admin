package auth

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type Roles struct {
	Openvpn bool `json:"openvpn"`
}

type Claims struct {
	jwt.StandardClaims
	Roles Roles `json:"roles"`
}

func getAuthCookie(r *http.Request) string {
	for _, c := range r.Cookies() {
		if c.Name == "auth" {
			return c.Value
		}
	}
	return ""
}

func HasReadRole(jwtData []byte, r *http.Request) bool {
	return JwtHasReadRole(jwtData, getAuthCookie(r))
}

func HasWriteRole(jwtData []byte, r *http.Request) bool {
	return JwtHasReadRole(jwtData, getAuthCookie(r))
}

func JwtHasReadRole(jwtData []byte, auth string) bool {
	if len(auth) <= 0 {
		return false
	}
	token, err := jwt.Parse(auth, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return jwtData, nil
	})

	if err != nil {
		fmt.Println("jwt invalid")
		return false
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		fmt.Println("claims invalid")
		return false
	}

	if !token.Valid {
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

func JwtUsername(jwtData []byte, r *http.Request) (bool, string) {
	auth := getAuthCookie(r)
	if len(auth) <= 0 {
		return false, ""
	}
	token, err := jwt.Parse(auth, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return jwtData, nil
	})

	if err != nil {
		fmt.Println("jwt invalid %s", err.Error())
		return false, err.Error()
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		fmt.Println("claims invalid")
		return false, ""
	}
	if !token.Valid {
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

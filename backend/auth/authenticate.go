package auth

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"rpiadm/backend/preference"
	"time"
)

func getEncryptedPasswordForUser(pref *preference.ApplicationConfig, username string) (string, error) {

	for _, value := range pref.Users {
		if value.Username == username {
			return value.Password, nil
		}
	}

	return "", errors.New("User not found")
}
func Authenticate(pref *preference.ApplicationConfig, username string, password string) error {

	expectedPassword, err := getEncryptedPasswordForUser(pref, username)
	if err != nil {
		return errors.New(fmt.Sprintf("Password error %v", err))
	}

	err = bcrypt.CompareHashAndPassword([]byte(expectedPassword), []byte(password))
	if err != nil {
		return errors.New("Username or password does not match")
	}

	return err
}

func BuildJwtCookie(pref *preference.ApplicationConfig, username string) (string, time.Time, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		StandardClaims: jwt.StandardClaims{
			Subject:   username,
			ExpiresAt: expirationTime.Unix(),
		},
		Roles: Roles{
			Openvpn: true,
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(pref.JwtData)
	if err != nil {
		return "", time.Time{}, errors.New(fmt.Sprintf("Can't sign payload: %s", err))
	}
	return tokenString, expirationTime, nil
}

package auth

import (
	"golang.org/x/crypto/bcrypt"
	"log"
	"rpiadm/backend/model"
	"time"
)

func HasValidApiKey(apiKeys []model.ApiKey, password string) *model.ApiKey {
	if len(password) == 0 {
		return nil
	}

	for _, apiKey := range apiKeys {
		if err := bcrypt.CompareHashAndPassword([]byte(apiKey.Key), []byte(password)); err == nil {
			if apiKey.Expires.Before(time.Now()) {
				log.Printf("skip expired apiKey '%s'\n", apiKey.Comment)
				return nil
			}
			return &apiKey
		}
	}
	log.Printf("password does not match any api key '%s'", password)
	return nil
}

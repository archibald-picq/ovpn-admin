package preference

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"rpiadm/backend/model"
	"time"
)

type ApiKeyUpdate struct {
	Comment string `json:"comment"`
	Key     string `json:"key"`
}

func getApiKeyExpirationTime() time.Time {
	return time.Now().Add(365 * 24 * time.Hour)
	//return time.Now().Add(5 * time.Minute)
}

func CreateApiKey(ovpnConfigDir string, preferences *model.ApplicationConfig, updates ApiKeyUpdate) (*model.ApiKey, error) {
	encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Key), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	apiKey := model.ApiKey{
		Id:      uuid.New(),
		Comment: updates.Comment,
		Key:     string(encoded),
		Expires: getApiKeyExpirationTime(),
	}
	preferences.ApiKeys = append(preferences.ApiKeys, apiKey)
	err = SavePreferences(ovpnConfigDir, preferences)
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

func DeleteApiKey(ovpnConfigDir string, preferences *model.ApplicationConfig, id uuid.UUID) error {
	for i, u := range preferences.ApiKeys {
		if u.Id == id {
			preferences.ApiKeys = RemoveIndexApiKey(preferences.ApiKeys, i)
			return SavePreferences(ovpnConfigDir, preferences)
		}
	}
	return errors.New(fmt.Sprintf("User %s not found", id))
}

func RemoveIndexApiKey(s []model.ApiKey, index int) []model.ApiKey {
	return append(s[:index], s[index+1:]...)
}

func UpdateApiKey(ovpnConfigDir string, preferences *model.ApplicationConfig, id uuid.UUID, updates ApiKeyUpdate) (*model.ApiKey, error) {
	for i, u := range preferences.ApiKeys {
		if u.Id == id {
			//preferences.ApiKeys[i].Key = updates.Key
			if len(updates.Key) == 0 {
				return nil, errors.New("must provide a string")
			}
			encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Key), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			preferences.ApiKeys[i].Key = string(encoded)
			preferences.ApiKeys[i].Comment = updates.Comment
			preferences.ApiKeys[i].Expires = getApiKeyExpirationTime()

			err = SavePreferences(ovpnConfigDir, preferences)
			if err != nil {
				return nil, err
			}
			return &(preferences.ApiKeys[i]), nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Api Key %s not found", id))
}

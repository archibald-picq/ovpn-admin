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

func CreateApiKey(ovpnConfigDir string, pref *ApplicationConfig, updates ApiKeyUpdate) (*model.ApiKey, error) {
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
	pref.ApiKeys = append(pref.ApiKeys, apiKey)
	err = pref.SavePreferences(ovpnConfigDir)
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

func DeleteApiKey(ovpnConfigDir string, pref *ApplicationConfig, id uuid.UUID) error {
	for i, u := range pref.ApiKeys {
		if u.Id == id {
			pref.ApiKeys = RemoveIndexApiKey(pref.ApiKeys, i)
			return pref.SavePreferences(ovpnConfigDir)
		}
	}
	return errors.New(fmt.Sprintf("User %s not found", id))
}

func RemoveIndexApiKey(s []model.ApiKey, index int) []model.ApiKey {
	return append(s[:index], s[index+1:]...)
}

func UpdateApiKey(ovpnConfigDir string, pref *ApplicationConfig, id uuid.UUID, updates ApiKeyUpdate) (*model.ApiKey, error) {
	for i, u := range pref.ApiKeys {
		if u.Id == id {
			//pref.ApiKeys[i].Key = updates.Key
			if len(updates.Key) == 0 {
				return nil, errors.New("must provide a string")
			}
			encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Key), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			pref.ApiKeys[i].Key = string(encoded)
			pref.ApiKeys[i].Comment = updates.Comment
			pref.ApiKeys[i].Expires = getApiKeyExpirationTime()

			err = pref.SavePreferences(ovpnConfigDir)
			if err != nil {
				return nil, err
			}
			return &(pref.ApiKeys[i]), nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Api Key %s not found", id))
}

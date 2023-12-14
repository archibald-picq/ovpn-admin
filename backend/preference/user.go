package preference

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"rpiadm/backend/model"
)

type AdminAccountUpdate struct {
	Username string  `json:"username"`
	Password string  `json:"password"`
	Name     *string `json:"name,omitempty"`
}

func CreateUser(ovpnConfigDir string, preferences *model.ApplicationConfig, updates AdminAccountUpdate) error {
	for _, u := range preferences.Users {
		if u.Username == updates.Username {
			return errors.New(fmt.Sprintf("User %s already exists", updates.Username))
		}
	}
	encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	preferences.Users = append(preferences.Users, model.Account{
		Username: updates.Username,
		Password: string(encoded),
		Name:     updates.Name,
	})
	return SavePreferences(ovpnConfigDir, preferences)
}

func DeleteUser(ovpnConfigDir string, preferences *model.ApplicationConfig, username string) error {
	for i, u := range preferences.Users {
		if u.Username == username {
			preferences.Users = RemoveIndex(preferences.Users, i)
			return SavePreferences(ovpnConfigDir, preferences)
		}
	}
	return errors.New(fmt.Sprintf("User %s not found", username))
}

func RemoveIndex(s []model.Account, index int) []model.Account {
	return append(s[:index], s[index+1:]...)
}

func UpdateUser(ovpnConfigDir string, preferences *model.ApplicationConfig, username string, updates AdminAccountUpdate) error {
	for i, u := range preferences.Users {
		if u.Username == username {
			preferences.Users[i].Username = updates.Username
			preferences.Users[i].Name = updates.Name
			if len(updates.Password) > 0 {
				encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Password), bcrypt.DefaultCost)
				if err != nil {
					return err
				}
				preferences.Users[i].Password = string(encoded)
			}
			return SavePreferences(ovpnConfigDir, preferences)
		}
	}
	return errors.New(fmt.Sprintf("User %s not found", username))
}

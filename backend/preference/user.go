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

func (pref *ApplicationConfig) CreateUser(ovpnConfigDir string, updates AdminAccountUpdate) error {
	for _, u := range pref.Users {
		if u.Username == updates.Username {
			return errors.New(fmt.Sprintf("User %s already exists", updates.Username))
		}
	}
	encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	pref.Users = append(pref.Users, model.Account{
		Username: updates.Username,
		Password: string(encoded),
		Name:     updates.Name,
	})
	return pref.SavePreferences(ovpnConfigDir)
}

func (pref *ApplicationConfig) DeleteUser(ovpnConfigDir string, username string) error {
	for i, u := range pref.Users {
		if u.Username == username {
			pref.Users = RemoveIndex(pref.Users, i)
			return pref.SavePreferences(ovpnConfigDir)
		}
	}
	return errors.New(fmt.Sprintf("User %s not found", username))
}

func RemoveIndex(s []model.Account, index int) []model.Account {
	return append(s[:index], s[index+1:]...)
}

func (pref *ApplicationConfig) UpdateUser(ovpnConfigDir string, username string, updates AdminAccountUpdate) error {
	for i, u := range pref.Users {
		if u.Username == username {
			pref.Users[i].Username = updates.Username
			pref.Users[i].Name = updates.Name
			if len(updates.Password) > 0 {
				encoded, err := bcrypt.GenerateFromPassword([]byte(updates.Password), bcrypt.DefaultCost)
				if err != nil {
					return err
				}
				pref.Users[i].Password = string(encoded)
			}
			return pref.SavePreferences(ovpnConfigDir)
		}
	}
	return errors.New(fmt.Sprintf("User %s not found", username))
}

func (pref *ApplicationConfig) GetUserProfile(username string) *model.ConfigPublicAccount {
	for _, u := range pref.Users {
		if u.Username == username {
			configPublicUser := new(model.ConfigPublicAccount)
			configPublicUser.Username = username
			if len(*u.Name) > 0 {
				configPublicUser.Name = u.Name
			}
			return configPublicUser
		}
	}
	return nil
}

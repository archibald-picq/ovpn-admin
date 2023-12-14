package auth

import (
	"rpiadm/backend/model"
)

func GetUserProfile(preference *model.ApplicationConfig, username string) *model.ConfigPublicAccount {
	for _, u := range preference.Users {
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

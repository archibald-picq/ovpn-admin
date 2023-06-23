package auth

import (
	"rpiadm/backend/model"
)

func GetUserProfile(preference *model.ApplicationConfig, username string) *model.ConfigPublicUser {
	for _, u := range preference.Users {
		if u.Username == username {
			configPublicUser := new(model.ConfigPublicUser)
			configPublicUser.Username = username
			configPublicUser.Name = u.Name
			return configPublicUser
		}
	}
	return nil
}

package openvpn

import (
	"errors"
	"fmt"
	"gopkg.in/alessio/shellescape.v1"
	"log"
	"rpiadm/backend/shell"
)

func SafeRestartServer(conf OvpnConfig) error {
	serverConfFile := conf.SourceFile

	backupFile := fmt.Sprintf("%s.backup", serverConfFile)
	initialServer := false
	if shell.FileExist(serverConfFile) {
		// make a backup of the original OpenVPN config file
		err := shell.FileCopy(serverConfFile, backupFile)
		if err != nil {
			return errors.New("can't backup config file")
		}
	} else {
		log.Printf("initial server")
		initialServer = true
	}

	//log.Printf("ensure ccd dir exists")
	err := CreateCcdIfNotExists(serverConfFile, &conf)
	if err != nil {
		log.Printf("fail to create ccd dir %s", err)
	}

	// overwrite original config file
	err = shell.WriteFile(serverConfFile, BuildConfig(conf))
	if err != nil {
		shell.FileCopy(backupFile, serverConfFile)
		return err
	}

	err = restartServer("server")
	if err != nil {
		// rollback config and restart server on error
		if shell.FileExist(backupFile) {
			shell.FileCopy(backupFile, serverConfFile)
			err = restartServer("server")
			shell.DeleteFile(backupFile)
		}
		// remove the config file if it fails to start for the first time
		if initialServer {
			shell.DeleteFile(serverConfFile)
		}
		return errors.New("fail to start service")
	}
	return nil
}

func restartServer(serviceName string) error {
	cmd := fmt.Sprintf("systemctl restart openvpn@%s.service", shellescape.Quote(serviceName))
	log.Printf("cmd %s", cmd)
	ret, err := shell.RunBash(cmd)
	if err != nil {
		log.Printf("cmd fails with: %s", ret)
	}
	return err
}

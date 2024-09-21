package openvpn

import (
	"rpiadm/backend/shell"
	"strings"
)

type Easyrsa struct {
	EasyrsaBinPath string
	EasyrsaDirPath string
}

func CheckEasyrsaVersionOrAbsent(easyrsa Easyrsa) string {
	if !shell.FileExist(easyrsa.EasyrsaBinPath) {
		return "absent"
	}
	output, error := shell.RunBash(easyrsa.EasyrsaBinPath + " --version")
	if error != nil {
		return "error"
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Version:") {
			line = strings.TrimSpace(line[len("Version:"):])
			return line
		}
	}
	return "error"
}

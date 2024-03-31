package openvpn

import (
	"rpiadm/backend/shell"
	"strings"
)

func IndexTxtParserCertificate(easyrsa Easyrsa) []*Certificate {
	txt := shell.ReadFile(easyrsa.EasyrsaDirPath + "/pki/index.txt")
	var indexTxt = make([]*Certificate, 0)

	txtLinesArray := strings.Split(txt, "\n")
	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) <= 0 {
			continue
		}
		switch {
		case strings.HasPrefix(str[0], "V"):
			identity := strings.Join(str[4:], " ")
			indexTxt = append(indexTxt, CreateClientCertificate(identity, "V", str[1], nil, str[2], str[3]))
		case strings.HasPrefix(str[0], "R"):
			identity := strings.Join(str[5:], " ")
			indexTxt = append(indexTxt, CreateClientCertificate(identity, "R", str[1], &str[2], str[3], str[4]))
		}
	}

	return indexTxt
}

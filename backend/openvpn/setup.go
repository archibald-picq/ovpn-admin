package openvpn

type ServerConfigVpn struct {
	ServiceName string             `json:"serviceName"`
	PkiPath     string             `json:"pkiPath"`
	PkiInit     *int               `json:"pkiCount"`
	DhPem       bool               `json:"dhPem"`
	CaCert      *IssuedCertificate `json:"caCert"`
	ServerCert  *IssuedCertificate `json:"serverCert"`
}

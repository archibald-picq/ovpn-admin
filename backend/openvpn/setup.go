package openvpn

type ServerConfigVpn struct {
	ServiceName string           `json:"serviceName"`
	PkiPath     string           `json:"pkiPath"`
	PkiInit     *int             `json:"pkiCount"`
	DhPem       bool             `json:"dhPem"`
	CaCert      *BaseCertificate `json:"caCert"`
	ServerCert  *BaseCertificate `json:"serverCert"`
}

package openvpn

import (
	"log"
)

type ConfigPublicSettings struct {
	ServiceName                string             `json:"serviceName"`
	Server                     string             `json:"server"`
	ForceGatewayIpv4           bool               `json:"forceGatewayIpv4"`
	ForceGatewayIpv4ExceptDhcp bool               `json:"forceGatewayIpv4ExceptDhcp"`
	ForceGatewayIpv4ExceptDns  bool               `json:"forceGatewayIpv4ExceptDns"`
	ServerIpv6                 *string            `json:"serverIpv6"`
	ForceGatewayIpv6           bool               `json:"forceGatewayIpv6"`
	ClientToClient             bool               `json:"clientToClient"`
	DuplicateCn                bool               `json:"duplicateCn"`
	CompLzo                    bool               `json:"compLzo"`
	Auth                       string             `json:"auth"`
	EnableMtu                  bool               `json:"enableMtu"`
	TunMtu                     int                `json:"tunMtu"`
	Routes                     []Route            `json:"routes"`
	RoutesPush                 []Route            `json:"routesPush"`
	Pushs                      []Push             `json:"pushs"`
	PushRoutes                 []string           `json:"pushRoutes"`
	DnsIpv4                    *string            `json:"dnsIpv4"`
	DnsIpv6                    *string            `json:"dnsIpv6"`
	ServerCommonName           string             `json:"serverCommonName"`
	CaCert                     *IssuedCertificate `json:"caCert"`
	ServerCert                 *IssuedCertificate `json:"serverCert"`
}

func (config *OvpnConfig) ExportServiceSettings(easyrsa Easyrsa) *ConfigPublicSettings {
	if config == nil {
		return nil
	}
	//log.Println("exporting settings %v", app.serverConf)
	var settings = new(ConfigPublicSettings)
	settings.ServiceName = config.ServiceName
	settings.Server = ConvertNetworkMaskCidr(config.Server)
	settings.ForceGatewayIpv4 = config.ForceGatewayIpv4
	settings.ForceGatewayIpv4ExceptDhcp = config.ForceGatewayIpv4ExceptDhcp
	settings.ForceGatewayIpv4ExceptDns = config.ForceGatewayIpv4ExceptDns
	settings.ServerIpv6 = config.ServerIpv6
	settings.ForceGatewayIpv6 = config.ForceGatewayIpv6
	settings.DuplicateCn = config.DuplicateCn
	settings.ClientToClient = config.ClientToClient
	settings.CompLzo = config.CompLzo
	settings.Routes = config.Routes
	settings.RoutesPush = config.RoutesPush
	settings.Auth = config.Auth
	settings.Pushs = config.Push
	settings.EnableMtu = config.EnableMtu
	settings.TunMtu = config.TunMtu
	settings.DnsIpv4 = config.DnsIpv4
	settings.DnsIpv6 = config.DnsIpv6
	settings.CaCert = config.caCert
	settings.ServerCert = config.ServerCert

	return settings
}

func ReadIssuedCertificateX509(path string) *IssuedCertificate {
	x509cert, err := ReadCertificateX509(path)
	if err != nil {
		log.Printf("can't read '%s' certificate", path)
		return nil
	}

	var cert IssuedCertificate
	cert.CommonName = x509cert.Subject.CommonName
	if len(x509cert.EmailAddresses) > 0 {
		cert.Email = x509cert.EmailAddresses[0]
	}
	if len(x509cert.Subject.Country) > 0 {
		cert.Country = x509cert.Subject.Country[0]
	}
	if len(x509cert.Subject.Province) > 0 {
		cert.Province = x509cert.Subject.Province[0]
	}
	if len(x509cert.Subject.Locality) > 0 {
		cert.City = x509cert.Subject.Locality[0]
	}
	if len(x509cert.Subject.Organization) > 0 {
		cert.Organisation = x509cert.Subject.Organization[0]
	}
	if len(x509cert.Subject.OrganizationalUnit) > 0 {
		cert.OrganisationUnit = x509cert.Subject.OrganizationalUnit[0]
	}
	cert.ExpiresAt = x509cert.NotAfter
	return &cert
}

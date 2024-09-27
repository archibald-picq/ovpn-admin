package model

import "rpiadm/backend/openvpn"

type ConfigPublicSettings struct {
	ServiceName                string          `json:"serviceName"`
	Server                     string          `json:"server"`
	ForceGatewayIpv4           bool            `json:"forceGatewayIpv4"`
	ForceGatewayIpv4ExceptDhcp bool            `json:"forceGatewayIpv4ExceptDhcp"`
	ForceGatewayIpv4ExceptDns  bool            `json:"forceGatewayIpv4ExceptDns"`
	ServerIpv6                 *string         `json:"serverIpv6"`
	ForceGatewayIpv6           bool            `json:"forceGatewayIpv6"`
	ClientToClient             bool            `json:"clientToClient"`
	DuplicateCn                bool            `json:"duplicateCn"`
	CompLzo                    bool            `json:"compLzo"`
	Auth                       string          `json:"auth"`
	EnableMtu                  bool            `json:"enableMtu"`
	TunMtu                     int             `json:"tunMtu"`
	Routes                     []openvpn.Route `json:"routes"`
	RoutesPush                 []openvpn.Route `json:"routesPush"`
	Pushs                      []openvpn.Push  `json:"pushs"`
	PushRoutes                 []string        `json:"pushRoutes"`
	DnsIpv4                    *string         `json:"dnsIpv4"`
	DnsIpv6                    *string         `json:"dnsIpv6"`
	ServerCommonName           string          `json:"serverCommonName"`
}

type ConfigPublicPreferences struct {
	Address             string                `json:"address"`
	DefaultAddress      string                `json:"defaultAddress"`
	CertificateDuration int                   `json:"certificateDuration"`
	ExplicitExitNotify  bool                  `json:"explicitExitNotify"`
	AuthNoCache         bool                  `json:"authNoCache"`
	VerifyX509Name      bool                  `json:"verifyX509Name"`
	Users               []ConfigPublicAccount `json:"users"`
	ApiKeys             []ConfigPublicApiKey  `json:"apiKeys"`
	AllowAnonymousCsr   bool                  `json:"allowAnonymousCsr"`
}

type ConfigPublicAccount struct {
	Username string  `json:"username"`
	Name     *string `json:"name,omitempty"`
}

type ConfigPublicApiKey struct {
	Id      string `json:"id"`
	Comment string `json:"comment"`
	Expires string `json:"expires"`
}

type ConfigPublicOpenvpn struct {
	Url            string                   `json:"url"`
	Settings       *ConfigPublicSettings    `json:"settings,omitempty"`
	Preferences    *ConfigPublicPreferences `json:"preferences,omitempty"`
	Unconfigured   *bool                    `json:"unconfigured,omitempty"`
	ServerSetup    *openvpn.ServerConfigVpn `json:"serverSetup,omitempty"`
	AllowSubmitCsr *bool                    `json:"allowSubmitCsr,omitempty"`
}

type ConfigPublic struct {
	User    *ConfigPublicAccount `json:"user,omitempty"`
	Openvpn ConfigPublicOpenvpn  `json:"openvpn"`
}

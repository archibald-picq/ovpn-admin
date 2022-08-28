package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ovpnServerCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_cert_expire",
		Help: "openvpn server certificate expire time in days",
	},
	)

	ovpnServerCaCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_ca_cert_expire",
		Help: "openvpn server CA certificate expire time in days",
	},
	)

	ovpnClientsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_total",
		Help: "total openvpn users",
	},
	)

	ovpnClientsRevoked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_revoked",
		Help: "revoked openvpn users",
	},
	)

	ovpnClientsExpired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_expired",
		Help: "expired openvpn users",
	},
	)

	ovpnClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_connected",
		Help: "total connected openvpn clients",
	},
	)

	ovpnUniqClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_uniq_clients_connected",
		Help: "uniq connected openvpn clients",
	},
	)

	ovpnClientCertificateExpire = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_cert_expire",
		Help: "openvpn user certificate expire time in days",
	},
		[]string{"client"},
	)

	ovpnClientConnectionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_info",
		Help: "openvpn user connection info. ip - assigned address from ovpn network. value - last time when connection was refreshed in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientConnectionFrom = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_from",
		Help: "openvpn user connection info. ip - from which address connection was initialized. value - time when connection was initialized in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientBytesReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_received",
		Help: "openvpn user bytes received",
	},
		[]string{"client"},
	)

	ovpnClientBytesSent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_sent",
		Help: "openvpn user bytes sent",
	},
		[]string{"client"},
	)
)

func (oAdmin *OvpnAdmin) registerMetrics() {
	oAdmin.promRegistry.MustRegister(ovpnServerCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnServerCaCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientsTotal)
	oAdmin.promRegistry.MustRegister(ovpnClientsRevoked)
	oAdmin.promRegistry.MustRegister(ovpnClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnUniqClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnClientsExpired)
	oAdmin.promRegistry.MustRegister(ovpnClientCertificateExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionInfo)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionFrom)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesReceived)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesSent)
}


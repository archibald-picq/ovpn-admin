client

dev tun
proto udp
{{- range $server := .Hosts }}
remote {{ $server.Host }} {{ $server.Port }}{{if $server.Protocol}} {{ $server.Protocol }}{{end}}
{{- end }}

resolv-retry infinite
nobind
persist-key
persist-tun

ns-cert-type server
comp-lzo
verb 4

#cipher AES-128-CBC
#key-direction 1
#redirect-gateway def1
#tls-client
#remote-cert-tls server
# uncomment below lines for use with linux
#script-security 2
# if you use resolved
#up /etc/openvpn/update-resolv-conf
#down /etc/openvpn/update-resolv-conf
# if you use systemd-resolved first install openvpn-systemd-resolved package
#up /etc/openvpn/update-systemd-resolved
#down /etc/openvpn/update-systemd-resolved

{{- if .PasswdAuth }}
auth-user-pass
{{- end }}

<cert>
{{ .Cert -}}
</cert>
<key>
{{ .Key -}}
</key>
<ca>
{{ .CA -}}
</ca>
{{if .TLS}}
<tls-auth>
{{ .TLS -}}
</tls-auth>
{{end}}

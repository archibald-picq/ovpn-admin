client
{{ if .ExplicitExitNotify -}}
explicit-exit-notify
{{- end }}
dev tun
proto udp
{{- range $server := .Hosts }}
remote {{ $server.Host }} {{ $server.Port }}{{if $server.Protocol}} {{ $server.Protocol }}{{end}}
{{- end }}

resolv-retry infinite
nobind
persist-key
persist-tun

remote-cert-tls server
{{ if .CompLzo -}}
comp-lzo
{{ end }}
verb 3

{{ if .CertCommonName -}}
verify-x509-name {{ .CertCommonName }} name
{{- end }}
{{ if .Auth -}}
auth {{ .Auth }}
{{- end }}
{{ if .AuthNocache -}}
auth-nocache
{{- end }}
{{ if .Cipher -}}
cipher {{ .Cipher }}
{{- end }}
{{ if .TlsClient -}}
tls-client
{{- end }}
{{ if .TlsVersionMin -}}
tls-version-min {{ .TlsVersionMin }}
{{- end }}
{{ if .TlsCipher -}}
tls-cipher {{ .TlsCipher }}
{{- end }}
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
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
{{- if .TLS}}
<tls-auth>
{{ .TLS -}}
</tls-auth>
{{end -}}
{{- if .TlsCrypt}}
<tls-crypt>
{{ .TlsCrypt -}}
</tls-crypt>
{{end -}}

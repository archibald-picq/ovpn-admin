{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} 255.255.255.0
{{- end }}
{{- range $route := .CustomRoutes }}
push "route {{ $route.Address }} {{ $route.Mask }}"{{if $route.Description}} # {{ $route.Description }}{{end}}
{{- end }}
{{- range $route := .CustomIRoutes }}
iroute {{ $route.Address }} {{ $route.Mask }}{{if $route.Description}} # {{ $route.Description }}{{end}}
{{- end }}

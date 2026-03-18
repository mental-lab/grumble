{{- define "grumble-agent.fullname" -}}
{{- printf "%s-%s" .Release.Name "grumble-agent" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "grumble-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "grumble-agent.fullname" . }}
{{- end }}
{{- end }}

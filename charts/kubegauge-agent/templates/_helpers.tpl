{{/* _helpers.tpl — nomes e labels padrão do kubegauge-agent. */}}
{{- define "kubegauge-agent.fullname" -}}
{{- if contains "kubegauge-agent" .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-kubegauge-agent" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kubegauge-agent.labels" -}}
app.kubernetes.io/name: kubegauge-agent
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kubegauge-agent.selectorLabels" -}}
app.kubernetes.io/name: kubegauge-agent
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kubegauge-agent.clusterName" -}}
{{- default .Release.Name .Values.clusterName -}}
{{- end -}}

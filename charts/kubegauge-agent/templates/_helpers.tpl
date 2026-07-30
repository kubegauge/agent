{{/* _helpers.tpl — standard names and labels for kubegauge-agent. */}}
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

{{/*
kubegauge-agent.apiKeySecretName is the Secret the API key is mounted from: one the operator
manages (existingSecret) or the one this chart creates.
*/}}
{{- define "kubegauge-agent.apiKeySecretName" -}}
{{- default (printf "%s-api-key" (include "kubegauge-agent.fullname" .)) .Values.existingSecret -}}
{{- end -}}

{{/*
kubegauge-agent.image resolves the full image reference. Release images are published as
ghcr.io/kubegauge/agent:v<semver> (WITH the leading "v"), so a bare semver — whether it came from
Chart.appVersion or from --set image.tag=0.16.0 — is prefixed here rather than turning into an
ImagePullBackOff. Anything that is not a bare semver (dev, latest, a branch name, a pre-release
built by hand) is passed through untouched.
*/}}
{{- define "kubegauge-agent.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if regexMatch "^[0-9]+\\.[0-9]+\\.[0-9]+" $tag -}}
{{- printf "%s:v%s" .Values.image.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

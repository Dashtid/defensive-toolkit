{{/*
Expand the name of the chart.
*/}}
{{- define "defensive-toolkit.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "defensive-toolkit.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "defensive-toolkit.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "defensive-toolkit.labels" -}}
helm.sh/chart: {{ include "defensive-toolkit.chart" . }}
{{ include "defensive-toolkit.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "defensive-toolkit.selectorLabels" -}}
app.kubernetes.io/name: {{ include "defensive-toolkit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "defensive-toolkit.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "defensive-toolkit.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the secret to use
*/}}
{{- define "defensive-toolkit.secretName" -}}
{{- if .Values.secrets.create }}
{{- include "defensive-toolkit.fullname" . }}
{{- else }}
{{- printf "%s-secrets" (include "defensive-toolkit.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Create the name of the configmap to use
*/}}
{{- define "defensive-toolkit.configMapName" -}}
{{- include "defensive-toolkit.fullname" . }}
{{- end }}

{{/*
Redis host - internal or external
*/}}
{{- define "defensive-toolkit.redisHost" -}}
{{- if .Values.redis.external }}
{{- .Values.redis.host }}
{{- else }}
{{- printf "%s-redis" (include "defensive-toolkit.fullname" .) }}
{{- end }}
{{- end }}

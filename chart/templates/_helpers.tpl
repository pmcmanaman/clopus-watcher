{{/*
Expand the name of the chart.
*/}}
{{- define "clopus-watcher.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "clopus-watcher.fullname" -}}
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
{{- define "clopus-watcher.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "clopus-watcher.labels" -}}
helm.sh/chart: {{ include "clopus-watcher.chart" . }}
{{ include "clopus-watcher.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "clopus-watcher.selectorLabels" -}}
app.kubernetes.io/name: {{ include "clopus-watcher.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Dashboard labels
*/}}
{{- define "clopus-watcher.dashboardLabels" -}}
helm.sh/chart: {{ include "clopus-watcher.chart" . }}
{{ include "clopus-watcher.dashboardSelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Dashboard selector labels
*/}}
{{- define "clopus-watcher.dashboardSelectorLabels" -}}
app.kubernetes.io/name: {{ include "clopus-watcher.name" . }}-dashboard
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: dashboard
{{- end }}

{{/*
Watcher labels
*/}}
{{- define "clopus-watcher.watcherLabels" -}}
helm.sh/chart: {{ include "clopus-watcher.chart" . }}
{{ include "clopus-watcher.watcherSelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Watcher selector labels
*/}}
{{- define "clopus-watcher.watcherSelectorLabels" -}}
app.kubernetes.io/name: {{ include "clopus-watcher.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: watcher
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "clopus-watcher.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "clopus-watcher.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the namespace name
*/}}
{{- define "clopus-watcher.namespace" -}}
{{- if .Values.namespace.create }}
{{- .Values.namespace.name }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Create the secret name for auth
*/}}
{{- define "clopus-watcher.authSecretName" -}}
{{- if eq .Values.auth.mode "api-key" }}
{{- if .Values.auth.apiKey.existingSecret }}
{{- .Values.auth.apiKey.existingSecret }}
{{- else }}
{{- include "clopus-watcher.fullname" . }}-auth
{{- end }}
{{- else if eq .Values.auth.mode "oauth-token" }}
{{- if .Values.auth.oauthToken.existingSecret }}
{{- .Values.auth.oauthToken.existingSecret }}
{{- else }}
{{- include "clopus-watcher.fullname" . }}-auth
{{- end }}
{{- else }}
{{- include "clopus-watcher.fullname" . }}-auth
{{- end }}
{{- end }}

{{/*
Create the PVC name
*/}}
{{- define "clopus-watcher.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- include "clopus-watcher.fullname" . }}-data
{{- end }}
{{- end }}

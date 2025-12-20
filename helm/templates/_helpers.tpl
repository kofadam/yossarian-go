{{/*
Expand the name of the chart.
*/}}
{{- define "yossarian-go.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "yossarian-go.fullname" -}}
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
{{- define "yossarian-go.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "yossarian-go.labels" -}}
helm.sh/chart: {{ include "yossarian-go.chart" . }}
{{ include "yossarian-go.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
environment: {{ .Values.global.environment }}
{{- end }}

{{/*
Selector labels for app
*/}}
{{- define "yossarian-go.selectorLabels" -}}
app.kubernetes.io/name: {{ include "yossarian-go.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for db-service
*/}}
{{- define "yossarian-go.dbSelectorLabels" -}}
app.kubernetes.io/name: {{ include "yossarian-go.name" . }}-db
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: database
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "yossarian-go.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "yossarian-go.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Database PVC name
*/}}
{{- define "yossarian-go.dbPvcName" -}}
{{- printf "%s-db-pvc" (include "yossarian-go.fullname" .) }}
{{- end }}

{{/*
Batch jobs PVC name
*/}}
{{- define "yossarian-go.batchPvcName" -}}
{{- printf "%s-batch-pvc" (include "yossarian-go.fullname" .) }}
{{- end }}

{{/*
App service name
*/}}
{{- define "yossarian-go.appServiceName" -}}
{{- printf "%s-service" (include "yossarian-go.fullname" .) }}
{{- end }}

{{/*
DB service name
*/}}
{{- define "yossarian-go.dbServiceName" -}}
{{- printf "%s-db-service" (include "yossarian-go.fullname" .) }}
{{- end }}

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
{{- end }}

{{/*
Selector labels
*/}}
{{- define "yossarian-go.selectorLabels" -}}
app.kubernetes.io/name: {{ include "yossarian-go.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
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
MinIO secret key (generate if not provided)
*/}}
{{- define "yossarian-go.minioSecretKey" -}}
{{- if .Values.minio.secretKey }}
{{- .Values.minio.secretKey }}
{{- else }}
{{- randAlphaNum 32 }}
{{- end }}
{{- end }}

{{/*
Frontend image
*/}}
{{- define "yossarian-go.frontend.image" -}}
{{- printf "%s:%s" .Values.images.app.repository (.Values.images.app.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Worker image
*/}}
{{- define "yossarian-go.worker.image" -}}
{{- printf "%s:%s" .Values.images.app.repository (.Values.images.app.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Database image
*/}}
{{- define "yossarian-go.database.image" -}}
{{- printf "%s:%s" .Values.images.database.repository (.Values.images.database.tag | default "latest") }}
{{- end }}

{{/*
MinIO image
*/}}
{{- define "yossarian-go.minio.image" -}}
{{- printf "%s:%s" .Values.minio.image.repository (.Values.minio.image.tag | default "latest") }}
{{- end }}

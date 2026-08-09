{{/* Expand the name of the chart. */}}
{{- define "aegis-kms.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name, capped at 63 chars for label compatibility. */}}
{{- define "aegis-kms.fullname" -}}
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

{{- define "aegis-kms.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "aegis-kms.labels" -}}
helm.sh/chart: {{ include "aegis-kms.chart" . }}
{{ include "aegis-kms.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "aegis-kms.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegis-kms.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "aegis-kms.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aegis-kms.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "aegis-kms.postgres.fullname" -}}
{{- printf "%s-postgres" (include "aegis-kms.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
JDBC URL for the journal and the audit table. In-chart Postgres addresses the headless service;
otherwise the operator-supplied URL is used verbatim.
*/}}
{{- define "aegis-kms.jdbcUrl" -}}
{{- if .Values.postgres.enabled -}}
jdbc:postgresql://{{ include "aegis-kms.postgres.fullname" . }}:5432/{{ .Values.postgres.auth.database }}
{{- else -}}
{{ required "postgres.external.jdbcUrl is required when postgres.enabled=false" .Values.postgres.external.jdbcUrl }}
{{- end -}}
{{- end }}

{{- define "aegis-kms.postgres.username" -}}
{{- if .Values.postgres.enabled -}}
{{ .Values.postgres.auth.username }}
{{- else -}}
{{ required "postgres.external.username is required when postgres.enabled=false" .Values.postgres.external.username }}
{{- end -}}
{{- end }}

{{- define "aegis-kms.postgres.secretName" -}}
{{- if .Values.postgres.enabled -}}
{{ required "postgres.auth.existingSecret is required — create it with `kubectl create secret generic <name> --from-literal=postgres-password=...`. The chart will not generate a database password that only Helm knows about." .Values.postgres.auth.existingSecret }}
{{- else -}}
{{ required "postgres.external.existingSecret is required when postgres.enabled=false" .Values.postgres.external.existingSecret }}
{{- end -}}
{{- end }}

{{- define "aegis-kms.postgres.secretKey" -}}
{{- if .Values.postgres.enabled -}}
{{ .Values.postgres.auth.secretKey }}
{{- else -}}
{{ .Values.postgres.external.secretKey }}
{{- end -}}
{{- end }}

{{/*
Fail fast on configurations the server itself would reject at boot, so the error arrives at
`helm install` time with a fixable message rather than as a CrashLoopBackOff.
*/}}
{{- define "aegis-kms.validate" -}}
{{- if and (eq .Values.aegis.auth.kind "dev") (eq .Values.aegis.preflight "enforce") -}}
{{- fail "aegis.auth.kind=dev cannot be used with aegis.preflight=enforce: the server's boot preflight will refuse to start. Set auth.kind=hmac (recommended) or preflight=warn for an evaluation cluster (see values-dev.yaml)." -}}
{{- end -}}
{{- if and (eq .Values.aegis.crypto.kind "software") (not .Values.persistence.enabled) -}}
{{- fail "aegis.crypto.kind=software requires persistence.enabled=true. Without a volume the keystore is regenerated on every restart and everything wrapped by the previous key becomes permanently unrecoverable." -}}
{{- end -}}
{{- if and (eq .Values.aegis.crypto.kind "in-memory") (eq .Values.aegis.preflight "enforce") -}}
{{- fail "aegis.crypto.kind=in-memory is not real cryptography and cannot be used with preflight=enforce. Use software (dev), aws-kms, or gcp-kms." -}}
{{- end -}}
{{- end }}

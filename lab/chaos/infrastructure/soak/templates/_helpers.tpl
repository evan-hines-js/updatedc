{{- define "soak.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}

{{- define "soak.labels" -}}
app.kubernetes.io/part-of: updatedc-chaos-lab
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{- /* The image's non-root identity. State ownership and the runtime UID must never drift. */ -}}
{{- define "soak.agentUid" -}}65532{{- end -}}

{{- /* Prepare a new volume once; never recursively widen durable 0600 keys on remount. */ -}}
{{- define "soak.podSecurityContext" -}}
fsGroup: {{ .uid }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile: {type: RuntimeDefault}
{{- end -}}

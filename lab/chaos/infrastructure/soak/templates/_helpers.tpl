{{- define "soak.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}

{{- define "soak.labels" -}}
app.kubernetes.io/part-of: updatedc-chaos-lab
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{- /* Image-owned identities. State ownership and the runtime UID must never drift. */ -}}
{{- define "soak.runtimeUid" -}}65532{{- end -}}
{{- define "soak.storageUid" -}}1000{{- end -}}

{{- /* The one security boundary for every non-root lab container. */ -}}
{{- define "soak.restrictedContainerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities: {drop: [ALL]}
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: {{ .uid }}
runAsGroup: {{ .uid }}
{{- end -}}

{{- /* Prepare a new volume once; never recursively widen durable 0600 keys on remount. */ -}}
{{- define "soak.podSecurityContext" -}}
fsGroup: {{ .uid }}
fsGroupChangePolicy: OnRootMismatch
seccompProfile: {type: RuntimeDefault}
{{- end -}}

{{- define "soak.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}

{{- define "soak.labels" -}}
app.kubernetes.io/part-of: updatedc-chaos-lab
app.kubernetes.io/managed-by: Helm
{{- end -}}

{{/* The release-scoped base name every object derives from. */}}
{{- define "updatec.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "updatec.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "updatec.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "updatec.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
The controller and the gateway run as SEPARATE identities. They are not equally trusted: the
controller reconciles the whole namespace and holds the publisher lease, while the gateway is the
only externally exposed listener and needs no more than agent enrollment. Giving the gateway the
controller's Role would hand an internet-facing process the ability to rewrite groups, sets, and
every status in the namespace.

Both names are therefore resolved HERE, in one place, and a render whose two names come out equal
is refused rather than emitted — the same treatment every other contradictory value pair in this
chart gets. `serviceAccount.create=false` used to fall back to the namespace `default`
ServiceAccount for BOTH workloads, which bound both Roles to one identity and quietly handed the
gateway everything above; bring-your-own ServiceAccounts must now be named explicitly.

    include "updatec.serviceAccountName" (dict "ctx" . "role" "controller")
*/}}
{{- define "updatec.serviceAccountName" -}}
{{- $ctx := .ctx -}}
{{- $accounts := $ctx.Values.serviceAccount -}}
{{- if and (not $accounts.create) (or (not $accounts.controllerName) (not $accounts.gatewayName)) -}}
{{- fail "serviceAccount.create is false, so both serviceAccount.controllerName and serviceAccount.gatewayName must name the ServiceAccounts you created. Leaving either empty would run that workload as the namespace `default` account, which is shared — and with both empty the controller's Role and the gateway's Role bind to the same identity, handing the internet-facing gateway namespace-wide writes." -}}
{{- end -}}
{{- $controller := default (printf "%s-controller" (include "updatec.fullname" $ctx)) $accounts.controllerName -}}
{{- $gateway := default (printf "%s-gateway" (include "updatec.fullname" $ctx)) $accounts.gatewayName -}}
{{- if eq $controller $gateway -}}
{{- fail (printf "serviceAccount.controllerName and serviceAccount.gatewayName both resolve to %q. The controller reconciles the whole namespace and the gateway is the only externally exposed listener, so one identity for both would bind the controller's Role to the gateway's pods. Name them separately." $controller) -}}
{{- end -}}
{{- if eq .role "controller" -}}{{- $controller -}}{{- else -}}{{- $gateway -}}{{- end -}}
{{- end -}}

{{- define "updatec.controllerServiceAccountName" -}}
{{- include "updatec.serviceAccountName" (dict "ctx" . "role" "controller") -}}
{{- end -}}

{{- define "updatec.gatewayServiceAccountName" -}}
{{- include "updatec.serviceAccountName" (dict "ctx" . "role" "gateway") -}}
{{- end -}}

{{/*
The one pod-level security context for every updatec workload. Kubernetes Secret projections are
owned by root; both binaries deliberately run as the same non-root UID. Making that UID the pod's
supplemental group lets credential volumes use 0440 instead of Kubernetes' world-readable 0644
default. A recursive fsGroup rewrite on every mount would also widen durable owner-only signing
keys from 0600 to 0660. `OnRootMismatch` prepares a new volume once, before any keys exist, and
never rewrites its contents afterward. Both fields are derived here and removed from the free-form
map, so a values override cannot weaken only one workload.
*/}}
{{- define "updatec.podSecurityContext" -}}
fsGroup: {{ required "securityContext.runAsUser is required so private Secret projections can be group-readable only" .Values.securityContext.runAsUser }}
fsGroupChangePolicy: OnRootMismatch
{{- omit .Values.podSecurityContext "fsGroup" "fsGroupChangePolicy" | toYaml | nindent 0 }}
{{- end -}}

{{/*
The image reference for one image value tree, and the only place this chart turns values into an
image reference. A digest names an exact image and a tag does not, so the two are mutually
exclusive here rather than silently resolved in favour of one. Nothing in this chart ever turns a
tag into a digest: that would require reaching a registry at render time, which breaks air-gapped
`helm template` and would make the rendered output depend on when it was rendered.

Every image the chart names goes through it, so a second image cannot end up governed by a weaker
copy of the same four rules. Call it with the tree and the name to quote in a refusal:

    include "updatec.imageRef" (dict "ctx" . "image" .Values.image "label" "image")
*/}}
{{- define "updatec.imageRef" -}}
{{- $image := .image -}}
{{- $label := .label -}}
{{- if $image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $image.digest) -}}
{{- fail (printf "%s.digest must be a full digest of the form sha256:<64 lowercase hex>, got %q. A malformed value would otherwise be pasted into an image reference that fails to pull on the node instead of failing here." $label $image.digest) -}}
{{- end -}}
{{- if $image.tag -}}
{{- fail (printf "%s.tag (%q) and %s.digest (%q) are both set. A digest already names an exact image, so a tag beside it is either redundant or a contradiction, and picking a winner silently is how a release ends up running something other than what it says. Set one." $label $image.tag $label $image.digest) -}}
{{- end -}}
{{- printf "%s@%s" $image.repository $image.digest -}}
{{- else -}}
{{- if $image.requireDigest -}}
{{- fail (printf "%s.requireDigest is set but %s.digest is empty: this release refuses mutable tags. Resolve the tag to a digest yourself and pass %s.digest — the chart will not resolve it for you, because that would require a registry at render time and break air-gapped rendering." $label $label $label) -}}
{{- end -}}
{{- printf "%s:%s" $image.repository (default .ctx.Chart.AppVersion $image.tag) -}}
{{- end -}}
{{- end -}}

{{/* The gateway's in-cluster Service name — also the name every object suffixes. */}}
{{- define "updatec.gatewayName" -}}
{{- printf "%s-gateway" (include "updatec.fullname" .) -}}
{{- end -}}

{{/* The pre-created CAS object that serializes enrollment across gateway replicas. */}}
{{- define "updatec.gatewayEnrollmentLeaseName" -}}
{{- $gateway := include "updatec.gatewayName" . -}}
{{- printf "%s-enroll-%s" ($gateway | trunc 46 | trimSuffix "-") ($gateway | sha256sum | trunc 8) -}}
{{- end -}}

{{- define "updatec.controllerName" -}}
{{- printf "%s-controller" (include "updatec.fullname" .) -}}
{{- end -}}

{{/*
Durable rollout-state index base. Five bytes are reserved for each `-a-00` shard suffix, so the
base must fit in 248 of Kubernetes' 253.

The truncate-and-hash rule for a repository name too long to spell verbatim is `bounded_child_name`
in crates/updatec/src/runtime.rs, and it is written there once. This chart deliberately carries no
second spelling of it: the value rendered here pins the controller's ConfigMap `resourceNames`
(rbac.yaml) and the admission policy's owned-state name predicate (controller-write-boundary.yaml),
so a copy that drifted from the Rust one — by a digest width, a retained length, a hash function —
would not fail to render. It would leave the controller `Forbidden` on every durable
admitted-state write, and publishing for that repository would stop with no rendering error to
point at. A name this chart cannot spell verbatim is therefore refused while rendering.
*/}}
{{- define "updatec.admittedConfigMapName" -}}
{{- $name := printf "updatec-admitted-%s" .Values.repository -}}
{{- if gt (len $name) 248 -}}
{{- fail (printf "repository %q is %d characters long. The chart grants the controller its durable rollout-state ConfigMaps by exact name, and `updatec-admitted-<repository>` must leave room for the shard suffix within a 253-character object name, so the repository may be at most 231 characters. Shorten it: the chart will not hash it down, because a second spelling of that rule here would drift from the controller's and turn into a Forbidden on every write instead of an error you can see." .Values.repository (len .Values.repository)) -}}
{{- end -}}
{{- $name -}}
{{- end -}}

{{/*
The environment both workloads share. `UPDATED_PUBLIC_URL` is minted into immutable signed
enrollment bundles, so it is validated here — once, for every consumer — rather than left to fail
as a node that cannot come back. Presence is not the whole check: nothing downstream parses the
value (the gateway appends a trailing slash and mints it verbatim), so the shape is checked here
too, to the same `^https://` rule install.sh and the Ansible role already enforce on the node side.
*/}}
{{- define "updatec.commonEnv" -}}
{{- if not .Values.publicUrl }}
{{- fail "publicUrl is required: it is the URL nodes are told to return to and it is baked into immutable signed enrollment bundles. Set it to the address agents resolve from outside the cluster." }}
{{- end }}
{{- if not (regexMatch "^https://[^\\s\"]+$" .Values.publicUrl) }}
{{- fail (printf "publicUrl must be an https URL, got %q. Enrollment is mutual TLS, and this exact string is minted into immutable signed bundles as the base every node returns to — a scheme-less or malformed value is not repaired by editing the release later, because a node refuses a bundle whose base URL changed." .Values.publicUrl) }}
{{- end }}
- name: UPDATED_NAMESPACE
  value: {{ .Release.Namespace | quote }}
- name: UPDATED_REPOSITORY
  value: {{ .Values.repository | quote }}
- name: UPDATED_PUBLIC_URL
  value: {{ .Values.publicUrl | quote }}
- name: RUST_LOG
  value: {{ .Values.logLevel | quote }}
{{- end -}}

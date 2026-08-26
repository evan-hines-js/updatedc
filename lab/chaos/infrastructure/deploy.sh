#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  echo 'This is internal; run lab/chaos/deploy.sh.' >&2
  exit 64
fi

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lab_root=$(cd "$here/.." && pwd)
terraform_dir="$here/terraform"
state_dir="$here/.state"
plan_only=false
reseed=false

usage() {
  cat <<'EOF'
Usage: lab/chaos/deploy.sh [--plan] [--reseed]

Builds and qualifies the isolated Proxmox/k3s chaos environment.

  --plan    verify inputs and write the exact Terraform plan without applying it
  --reseed  destroy all product and campaign state before rebuilding the lab
  -h        show this help
EOF
}

while (( $# )); do
  case "$1" in
    --plan) plan_only=true ;;
    --reseed) reseed=true ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done
if $plan_only && $reseed; then
  echo '--plan and --reseed are mutually exclusive.' >&2
  exit 64
fi

if [[ -z ${UPDATEDC_CHAOS_CONFIG:-} && -r "$lab_root/deploy.env" ]]; then
  UPDATEDC_CHAOS_CONFIG="$lab_root/deploy.env"
fi
if [[ -n ${UPDATEDC_CHAOS_CONFIG:-} ]]; then
  [[ -r "$UPDATEDC_CHAOS_CONFIG" ]] || { echo "Unreadable config: $UPDATEDC_CHAOS_CONFIG" >&2; exit 66; }
  # shellcheck source=/dev/null
  source "$UPDATEDC_CHAOS_CONFIG"
fi

: "${TF_VAR_proxmox_api_token:?set the least-privilege Proxmox API token}"
: "${UPDATEDC_CHAOS_SSH_KEY:?set the chaos-lab guest SSH private key}"
: "${UPDATEDC_CHAOS_K3S_BINARY:?set the checksum-pinned k3s binary}"
: "${UPDATEDC_CHAOS_K3S_SHA256:?set the k3s SHA-256}"
: "${UPDATEDC_CHAOS_MESH_CHART:?set the checksum-pinned Chaos Mesh chart}"
: "${UPDATEDC_CHAOS_MESH_CHART_SHA256:?set the Chaos Mesh chart SHA-256}"
: "${UPDATEDC_CHAOS_MONITORING_CHART:?set the checksum-pinned kube-prometheus-stack chart}"
: "${UPDATEDC_CHAOS_MONITORING_CHART_SHA256:?set the monitoring chart SHA-256}"
: "${TF_VAR_proxmox_node_name:=poweredge-md}"
: "${TF_VAR_proxmox_node_address:=10.0.0.206}"
: "${TF_VAR_proxmox_ssh_username:=root}"
: "${TF_VAR_guest_image_file_id:=local:iso/ubuntu-24.04-server-cloudimg-amd64.img}"
: "${TF_VAR_guest_image_sha256:=d1940f7d69d343355e183dff1e08a59852d32e7309baa7a4bad8365b11b005ac}"
export TF_VAR_proxmox_node_name TF_VAR_proxmox_node_address TF_VAR_proxmox_ssh_username
export TF_VAR_guest_image_file_id TF_VAR_guest_image_sha256

for command in tofu ansible-playbook jq ssh ssh-keygen openssl helm kubectl curl git; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 69; }
done
for artifact in \
  "$UPDATEDC_CHAOS_SSH_KEY" \
  "$UPDATEDC_CHAOS_K3S_BINARY" \
  "$UPDATEDC_CHAOS_MESH_CHART" \
  "$UPDATEDC_CHAOS_MONITORING_CHART"; do
  [[ -f $artifact && ! -L $artifact && -r $artifact ]] || {
    echo "Artifact must be a readable regular non-symlink: $artifact" >&2
    exit 66
  }
done
[[ $UPDATEDC_CHAOS_K3S_SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid k3s SHA-256.' >&2; exit 64; }
[[ $UPDATEDC_CHAOS_MESH_CHART_SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid chart SHA-256.' >&2; exit 64; }
[[ $UPDATEDC_CHAOS_MONITORING_CHART_SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid monitoring chart SHA-256.' >&2; exit 64; }
[[ $TF_VAR_guest_image_sha256 =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid guest-image SHA-256.' >&2; exit 64; }
[[ $TF_VAR_proxmox_node_address =~ ^[A-Za-z0-9.-]+$ ]] || { echo 'Invalid Proxmox SSH address.' >&2; exit 64; }
[[ $TF_VAR_proxmox_node_name =~ ^[A-Za-z0-9._-]+$ ]] || { echo 'Invalid Proxmox node name.' >&2; exit 64; }
[[ $TF_VAR_proxmox_ssh_username =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] || { echo 'Invalid Proxmox SSH user.' >&2; exit 64; }
[[ $TF_VAR_guest_image_file_id =~ ^[A-Za-z0-9._-]+:iso/[A-Za-z0-9._-]+$ ]] || {
  echo 'Invalid guest-image volume ID.' >&2
  exit 64
}

actual_k3s_sha=$(openssl dgst -sha256 -r "$UPDATEDC_CHAOS_K3S_BINARY" | awk '{print $1}')
[[ $actual_k3s_sha == "$UPDATEDC_CHAOS_K3S_SHA256" ]] || { echo 'k3s artifact checksum mismatch.' >&2; exit 65; }
actual_chart_sha=$(openssl dgst -sha256 -r "$UPDATEDC_CHAOS_MESH_CHART" | awk '{print $1}')
[[ $actual_chart_sha == "$UPDATEDC_CHAOS_MESH_CHART_SHA256" ]] || { echo 'Chaos Mesh chart checksum mismatch.' >&2; exit 65; }
actual_monitoring_chart_sha=$(openssl dgst -sha256 -r "$UPDATEDC_CHAOS_MONITORING_CHART" | awk '{print $1}')
[[ $actual_monitoring_chart_sha == "$UPDATEDC_CHAOS_MONITORING_CHART_SHA256" ]] || {
  echo 'Monitoring chart checksum mismatch.' >&2
  exit 65
}

guest_image_name=${TF_VAR_guest_image_file_id#*:iso/}
# Every interpolated remote-command value is constrained above to a simple token.
# shellcheck disable=SC2029
remote_guest_sha=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  "$TF_VAR_proxmox_ssh_username@$TF_VAR_proxmox_node_address" \
  "sha256sum /var/lib/vz/template/iso/$guest_image_name" | awk '{print $1}')
[[ $remote_guest_sha == "$TF_VAR_guest_image_sha256" ]] || {
  echo 'Cached Proxmox guest image checksum mismatch.' >&2
  exit 65
}

guest_public_key=$(ssh-keygen -y -f "$UPDATEDC_CHAOS_SSH_KEY")
[[ $guest_public_key == ssh-* ]] || { echo 'Could not derive an OpenSSH public key.' >&2; exit 65; }
TF_VAR_proxmox_ssh_private_key=$(<"$UPDATEDC_CHAOS_SSH_KEY")
TF_VAR_ssh_public_keys=$(jq -cn --arg key "$guest_public_key updatedc-chaos" '[$key]')
export TF_VAR_proxmox_ssh_private_key TF_VAR_ssh_public_keys

mkdir -p "$state_dir"
chmod 0700 "$state_dir"
lock_dir="$state_dir/deploy.lock"
mkdir "$lock_dir" 2>/dev/null || { echo 'Another chaos-lab deployment is active.' >&2; exit 75; }
trap 'rmdir "$lock_dir" 2>/dev/null || true' EXIT

tofu -chdir="$terraform_dir" fmt -check
tofu -chdir="$terraform_dir" init
tofu -chdir="$terraform_dir" validate
tofu -chdir="$terraform_dir" plan -out="$state_dir/chaos.tfplan"
if $plan_only; then
  echo "Plan written to $state_dir/chaos.tfplan"
  exit 0
fi
tofu -chdir="$terraform_dir" apply "$state_dir/chaos.tfplan"

command -v docker >/dev/null || { echo 'docker is required to build the source under test' >&2; exit 69; }
source_tree="$lab_root/../.."
fingerprint_source() {
  local executable source_file
  {
    while IFS= read -r -d '' source_file; do
      [[ -e $source_tree/$source_file ]] || continue
      [[ -f $source_tree/$source_file && ! -L $source_tree/$source_file && -r $source_tree/$source_file ]] || {
        echo "Image input must be a readable regular non-symlink: $source_file" >&2
        return 66
      }
      executable=0
      [[ -x $source_tree/$source_file ]] && executable=1
      printf '%s\0%s\0' "$source_file" "$executable"
      openssl dgst -sha256 -r "$source_tree/$source_file" | awk '{print $1}'
    done < <(git -C "$source_tree" ls-files --cached --others --exclude-standard -z -- "$@")
  } | openssl dgst -sha256 -r | awk '{print substr($1, 1, 20)}'
}
common_image_inputs=(.dockerignore Cargo.toml Cargo.lock rust-toolchain.toml .cargo crates)
control_fingerprint=$(fingerprint_source "${common_image_inputs[@]}")
e2e_fingerprint=$(fingerprint_source \
  "${common_image_inputs[@]}" \
  scripts/lib/publish-fuzz-plan.sh \
  scripts/haproxy)
[[ $control_fingerprint =~ ^[0-9a-f]{20}$ && $e2e_fingerprint =~ ^[0-9a-f]{20}$ ]] || {
  echo 'Could not fingerprint the image build inputs.' >&2
  exit 70
}
control_image="updatec-chaos-control:$control_fingerprint"
e2e_image="updatec-chaos-e2e:$e2e_fingerprint"
artifact_dir="$state_dir/artifacts"
mkdir -p "$artifact_dir"
control_archive="$artifact_dir/updatec-chaos-control-$control_fingerprint.tar"
e2e_archive="$artifact_dir/updatec-chaos-e2e-$e2e_fingerprint.tar"
if [[ ! -f $control_archive ]]; then
  docker build --platform linux/amd64 --file "$lab_root/../../crates/updatec/Dockerfile" \
    --tag "$control_image" "$lab_root/../.."
  docker save --output "$control_archive" "$control_image"
fi
if [[ ! -f $e2e_archive ]]; then
  docker build --platform linux/amd64 --file "$lab_root/../../crates/updatec/Dockerfile.e2e" \
    --tag "$e2e_image" "$lab_root/../.."
  docker save --output "$e2e_archive" "$e2e_image"
fi
control_archive_sha256=$(openssl dgst -sha256 -r "$control_archive" | awk '{print $1}')
e2e_archive_sha256=$(openssl dgst -sha256 -r "$e2e_archive" | awk '{print $1}')

"$here/render-ansible-inventory.sh"
export UPDATEDC_CHAOS_SSH_KEY
ANSIBLE_CONFIG="$here/ansible/ansible.cfg" ansible-playbook \
  -i "$state_dir/inventory.json" \
  --extra-vars "updatedc_chaos_k3s_binary=$UPDATEDC_CHAOS_K3S_BINARY" \
  --extra-vars "updatedc_chaos_k3s_sha256=$UPDATEDC_CHAOS_K3S_SHA256" \
  --extra-vars "updatedc_chaos_state_dir=$state_dir" \
  --extra-vars "updatedc_chaos_control_image_archive=$control_archive" \
  --extra-vars "updatedc_chaos_control_image_sha256=$control_archive_sha256" \
  --extra-vars "updatedc_chaos_e2e_image_archive=$e2e_archive" \
  --extra-vars "updatedc_chaos_e2e_image_sha256=$e2e_archive_sha256" \
  "$here/ansible/site.yml"

export KUBECONFIG="$state_dir/kubeconfig.yaml"

if $reseed; then
  echo 'Reseeding the isolated product namespace...'
  # Stop only the campaign first so it cannot recreate its repository. Keep both the controller
  # and object storage alive until the controller has completed the one canonical repository
  # finalization path. A timeout deliberately leaves the lab intact for diagnosis.
  if helm status updatec-soak --namespace updated-system >/dev/null 2>&1; then
    kubectl -n updated-system delete deployment updatec-soak --wait=true --timeout=8m
  fi
  if kubectl get namespace updated-system >/dev/null 2>&1 &&
     kubectl -n updated-system get updaterepository default >/dev/null 2>&1; then
    kubectl -n updated-system delete updaterepository default --wait=true --timeout=5m
  fi
  if helm status updatec-soak --namespace updated-system >/dev/null 2>&1; then
    helm uninstall updatec-soak --namespace updated-system --wait --timeout 10m
  fi
  if helm status updatec --namespace updated-system >/dev/null 2>&1; then
    helm uninstall updatec --namespace updated-system --wait --timeout 10m
  fi
  if kubectl get namespace updated-system >/dev/null 2>&1; then
    kubectl delete namespace updated-system --wait=true --timeout=10m
  fi
fi

soak_metrics() {
  kubectl get --raw \
    /api/v1/namespaces/updated-system/services/http:updatec-soak-metrics:9091/proxy/metrics
}

soak_metric() {
  local exposition=$1 name=$2
  awk -v name="$name" '$1 == name { print $2; found = 1 } END { if (!found) exit 1 }' \
    <<<"$exposition"
}

soak_fault_sum() {
  local exposition=$1 series=$2
  awk -v series="$series" '
    index($1, series "{") == 1 { sum += $2; found = 1 }
    END { if (!found) exit 1; printf "%.0f\n", sum }
  ' <<<"$exposition"
}

helm upgrade --install chaos-mesh "$UPDATEDC_CHAOS_MESH_CHART" \
  --namespace chaos-mesh --create-namespace \
  --values "$here/chaos-mesh-values.yaml" \
  --wait --timeout 5m
kubectl -n chaos-mesh rollout status deployment/chaos-controller-manager --timeout=300s
kubectl -n chaos-mesh rollout status daemonset/chaos-daemon --timeout=300s

daemon_count=$(kubectl -n chaos-mesh get daemonset chaos-daemon -o jsonpath='{.status.numberReady}')
[[ $daemon_count == 4 ]] || { echo "Expected four ready chaos daemons, got $daemon_count." >&2; exit 1; }

kubectl apply -f "$lab_root/../../deploy/charts/updatec/crds/"
kubectl create namespace updated-system --dry-run=client -o yaml | kubectl apply -f -
kubectl annotate namespace updated-system chaos-mesh.org/inject=enabled --overwrite

pki_dir="$state_dir/pki"
mkdir -p "$pki_dir"
if [[ ! -s $pki_dir/ca.key || ! -s $pki_dir/ca.crt ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$pki_dir/ca.key"
  openssl req -x509 -new -key "$pki_dir/ca.key" -sha256 -days 3650 \
    -subj '/CN=updatedc-chaos-fleet-ca' -out "$pki_dir/ca.crt"
fi
if [[ ! -s $pki_dir/gateway.key || ! -s $pki_dir/gateway.crt ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$pki_dir/gateway.key"
  openssl req -new -key "$pki_dir/gateway.key" -subj '/CN=updatec-gateway' \
    -out "$pki_dir/gateway.csr"
  cat >"$pki_dir/gateway.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:updatec-gateway,DNS:updatec-gateway.updated-system,DNS:updatec-gateway.updated-system.svc,DNS:minio-direct.updated-system.svc,DNS:release-default,DNS:release-soak-a,DNS:release-soak-b,DNS:release-soak-c,DNS:release-server
EOF
  openssl x509 -req -in "$pki_dir/gateway.csr" -CA "$pki_dir/ca.crt" \
    -CAkey "$pki_dir/ca.key" -CAcreateserial -days 825 -sha256 \
    -extfile "$pki_dir/gateway.ext" -out "$pki_dir/gateway.crt"
fi
if [[ ! -s $pki_dir/agent.key || ! -s $pki_dir/agent.crt ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$pki_dir/agent.key"
  openssl req -new -key "$pki_dir/agent.key" -subj '/CN=updated-agent' \
    -out "$pki_dir/agent.csr"
  cat >"$pki_dir/agent.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
  openssl x509 -req -in "$pki_dir/agent.csr" -CA "$pki_dir/ca.crt" \
    -CAkey "$pki_dir/ca.key" -CAcreateserial -days 825 -sha256 \
    -extfile "$pki_dir/agent.ext" -out "$pki_dir/agent.crt"
fi
kubectl -n updated-system create secret generic fleet-ca \
  --from-file=tls.crt="$pki_dir/ca.crt" --from-file=tls.key="$pki_dir/ca.key" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n updated-system create secret generic gateway-tls \
  --from-file=tls.crt="$pki_dir/gateway.crt" --from-file=tls.key="$pki_dir/gateway.key" \
  --from-file=ca.crt="$pki_dir/ca.crt" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n updated-system create secret generic agent-tls \
  --from-file=tls.crt="$pki_dir/agent.crt" --from-file=tls.key="$pki_dir/agent.key" \
  --from-file=ca.crt="$pki_dir/ca.crt" --dry-run=client -o yaml | kubectl apply -f -

s3_password_file="$state_dir/minio-root-password"
if [[ ! -s $s3_password_file ]]; then
  temporary_s3_password=$(mktemp "$state_dir/.minio-root-password.XXXXXX")
  openssl rand -hex 24 >"$temporary_s3_password"
  chmod 0600 "$temporary_s3_password"
  mv "$temporary_s3_password" "$s3_password_file"
fi
s3_password=$(<"$s3_password_file")
[[ $s3_password =~ ^[0-9a-f]{48}$ ]] || { echo 'MinIO password state is invalid.' >&2; exit 65; }
kubectl -n updated-system create secret generic s3-credentials \
  --from-literal=AWS_ACCESS_KEY_ID=updatedc-chaos \
  --from-literal=AWS_SECRET_ACCESS_KEY="$s3_password" \
  --dry-run=client -o yaml | kubectl apply -f -

# A deploy is qualified only by a new campaign round. Capture the durable counters before changing
# anything; a historical success cannot certify the binaries and manifests being installed now.
metrics_before=$(soak_metrics 2>/dev/null || true)
successful_campaigns_before=$(soak_metric "$metrics_before" updatec_soak_successful_campaigns_total 2>/dev/null || printf '0\n')
faults_before=$(soak_fault_sum "$metrics_before" updatec_soak_faults_total 2>/dev/null || printf '0\n')

# Install the product first, then the complete campaign exactly once. The gateway and launchers
# reconcile while the campaign creates the repository and enrollment state; only require their
# readiness after that bootstrap, so deployment has no alternate agents-off topology or ordering
# deadlock.
helm upgrade --install updatec "$lab_root/../../deploy/charts/updatec" \
  --namespace updated-system \
  --values "$here/updatec-values.yaml" \
  --set image.repository=updatec-chaos-control --set image.tag="$control_fingerprint" \
  --set healthproxy.image.repository=updatec-chaos-e2e \
  --set healthproxy.image.tag="$e2e_fingerprint"
kubectl -n updated-system rollout status deployment/updatec-controller --timeout=600s
helm upgrade --install updatec-soak "$here/soak" --namespace updated-system \
  --set image.repository=updatec-chaos-e2e --set image.tag="$e2e_fingerprint" \
  --set agents.enabled=true --wait --timeout 15m
kubectl -n updated-system rollout status deployment/updatec-gateway --timeout=600s
kubectl -n updated-system rollout status statefulset/agent --timeout=900s
configured_agents=$(kubectl -n updated-system get statefulset agent -o jsonpath='{.spec.replicas}')
[[ $configured_agents =~ ^[1-9][0-9]*$ ]] || {
  echo "The campaign StatefulSet has an invalid replica count: $configured_agents" >&2
  exit 65
}

grafana_password_file="$state_dir/grafana-admin-password"
if [[ ! -s $grafana_password_file ]]; then
  temporary_password=$(mktemp "$state_dir/.grafana-admin-password.XXXXXX")
  temporary_password_value=$(openssl rand -base64 32)
  printf '%s' "$temporary_password_value" >"$temporary_password"
  chmod 0600 "$temporary_password"
  mv "$temporary_password" "$grafana_password_file"
fi
grafana_password=$(<"$grafana_password_file")
grafana_password_size=$(wc -c <"$grafana_password_file" | tr -d '[:space:]')
[[ $grafana_password =~ ^[A-Za-z0-9+/]{43}=$ && $grafana_password_size == "${#grafana_password}" ]] || {
  echo 'Grafana password must be one exact 32-byte base64 token with no line ending.' >&2
  exit 65
}
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
kubectl -n monitoring create secret generic updatedc-grafana-admin \
  --from-literal=admin-user=admin \
  --from-file=admin-password="$grafana_password_file" \
  --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install monitoring "$UPDATEDC_CHAOS_MONITORING_CHART" \
  --namespace monitoring \
  --values "$here/monitoring-values.yaml" \
  --wait --timeout 10m
kubectl apply -f "$here/observability.yaml"
kubectl apply -f "$here/soak-observability.yaml"
kubectl -n monitoring rollout status deployment/monitoring-grafana --timeout=300s
printf '%s\n' "$grafana_password" | \
  kubectl -n monitoring exec -i deployment/monitoring-grafana -c grafana -- \
    grafana cli admin reset-admin-password --password-from-stdin >/dev/null

grafana_node=$(kubectl -n monitoring get pod \
  -l app.kubernetes.io/name=grafana \
  -o jsonpath='{.items[0].spec.nodeName}')
[[ $grafana_node == updatedc-chaos-control ]] || {
  echo "Grafana is on $grafana_node, not the declared control node." >&2
  exit 1
}
prometheus_node=$(kubectl -n monitoring get pod \
  -l app.kubernetes.io/name=prometheus \
  -o jsonpath='{.items[0].spec.nodeName}')
[[ $prometheus_node == updatedc-chaos-storage ]] || {
  echo "Prometheus is on $prometheus_node, not the declared storage node." >&2
  exit 1
}
grafana_service=$(kubectl -n monitoring get service monitoring-grafana -o json)
jq -e '
  .spec.type == "NodePort" and
  .spec.externalTrafficPolicy == "Local" and
  (.spec.ports | length) == 1 and
  .spec.ports[0].nodePort == 30300
' <<<"$grafana_service" >/dev/null || {
  echo 'Grafana is not exclusively exposed on local NodePort 30300.' >&2
  exit 1
}
curl --fail --silent --show-error --max-time 10 \
  http://10.0.0.250:30300/api/health | jq -e '.database == "ok"' >/dev/null
curl --fail --silent --show-error --max-time 10 \
  --user "admin:$grafana_password" \
  http://10.0.0.250:30300/api/user | \
  jq -e '.login == "admin" and .isGrafanaAdmin == true' >/dev/null

UPDATEDC_CHAOS_INTERNAL=1 "$here/qualify.sh"

qualification_deadline=$((SECONDS + 900))
qualification_attempt=0
campaign_qualified=false
while (( SECONDS < qualification_deadline )); do
  current_metrics=$(soak_metrics 2>/dev/null || true)
  successful_campaigns=$(soak_metric "$current_metrics" updatec_soak_successful_campaigns_total 2>/dev/null || printf '0\n')
  faults=$(soak_fault_sum "$current_metrics" updatec_soak_faults_total 2>/dev/null || printf '0\n')
  active_faults=$(soak_fault_sum "$current_metrics" updatec_soak_fault_active 2>/dev/null || printf '1\n')
  recovery_pending=$(soak_metric "$current_metrics" updatec_soak_recovery_pending 2>/dev/null || printf '1\n')
  forward_recovery_pending=$(soak_metric "$current_metrics" updatec_soak_forward_recovery_pending 2>/dev/null || printf '1\n')
  campaign_healthy=$(soak_metric "$current_metrics" updatec_soak_campaign_healthy 2>/dev/null || printf '0\n')
  expected_nodes=$(soak_metric "$current_metrics" updatec_soak_fleet_expected_nodes 2>/dev/null || printf '0\n')
  converged_nodes=$(soak_metric "$current_metrics" updatec_soak_fleet_converged_nodes 2>/dev/null || printf '0\n')
  for value in "$successful_campaigns" "$faults" "$active_faults" "$recovery_pending" "$forward_recovery_pending" "$campaign_healthy" "$expected_nodes" "$converged_nodes"; do
    [[ $value =~ ^[0-9]+$ ]] || { echo "Campaign published a non-integer qualification metric: $value" >&2; exit 65; }
  done

  if (( successful_campaigns > successful_campaigns_before &&
        faults > faults_before &&
        active_faults == 0 &&
        recovery_pending == 0 &&
        forward_recovery_pending == 0 &&
        campaign_healthy == 1 &&
        expected_nodes == configured_agents &&
        converged_nodes == expected_nodes )); then
    echo "Permanent campaign qualified: a new faulted round converged all $expected_nodes agents and recovered cleanly."
    campaign_qualified=true
    break
  fi

  if (( qualification_attempt % 6 == 0 )); then
    echo "Waiting for a new permanent campaign success (successes $successful_campaigns/$((successful_campaigns_before + 1)), faults $faults/$((faults_before + 1)), recovery_pending $recovery_pending/$forward_recovery_pending, fleet $converged_nodes/$expected_nodes)..."
  fi
  qualification_attempt=$((qualification_attempt + 1))
  sleep 5
done
if ! $campaign_qualified; then
  echo 'Permanent campaign did not complete a new faulted, fully recovered round within 15 minutes.' >&2
  kubectl -n updated-system logs deployment/updatec-soak --tail=200 >&2 || true
  exit 1
fi

echo "updatec chaos lab is ready; kubeconfig: $KUBECONFIG"
echo "Grafana: http://10.0.0.250:30300 (admin password: $grafana_password_file)"

#!/usr/bin/env bash
set -euo pipefail
umask 077

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
terraform_dir="$here/terraform"
state_dir="$here/.state"
: "${UPDATEDC_CHAOS_SSH_KEY:?set UPDATEDC_CHAOS_SSH_KEY}"
mkdir -p "$state_dir"
chmod 0700 "$state_dir"

inventory=$(tofu -chdir="$terraform_dir" output -json inventory)
proxmox_host=$(tofu -chdir="$terraform_dir" output -json proxmox_host)
jq -e 'length == 4 and all(.[]; (.address | type) == "string" and (.vm_id | type) == "number")' \
  <<<"$inventory" >/dev/null
jq -e '.name and .address and .user' <<<"$proxmox_host" >/dev/null

known_hosts="$state_dir/known_hosts"
temporary_known_hosts=$(mktemp "$state_dir/.known-hosts.XXXXXX")
temporary_inventory=$(mktemp "$state_dir/.inventory.XXXXXX")
trap 'rm -f "$temporary_known_hosts" "$temporary_inventory"' EXIT
chmod 0600 "$temporary_known_hosts" "$temporary_inventory"

valid_ed25519_public_key() {
  local key=$1
  [[ $key != *$'\n'* && $key == ssh-ed25519\ * ]] &&
    ssh-keygen -l -E sha256 -f <(printf '%s\n' "$key") >/dev/null 2>&1
}

pve_address=$(jq -er .address <<<"$proxmox_host")
pve_name=$(jq -er .name <<<"$proxmox_host")
pve_user=$(jq -er .user <<<"$proxmox_host")
pve_keys=$(ssh-keygen -F "$pve_address" 2>/dev/null | sed '/^#/d')
[[ -n "$pve_keys" ]] || {
  printf 'Proxmox node %s (%s) is not pinned in the operator known_hosts.\n' "$pve_name" "$pve_address" >&2
  exit 77
}
printf '%s\n' "$pve_keys" >"$temporary_known_hosts"

# Trust each guest only after obtaining its key through the already-authenticated
# Proxmox/QEMU-agent channel. Network key discovery is never used.
while IFS=$'\t' read -r address vm_id name; do
  [[ "$vm_id" =~ ^[0-9]+$ ]] || { echo "invalid VM ID: $vm_id" >&2; exit 65; }
  guest_key=
  for _attempt in {1..60}; do
    # vm_id is constrained to digits before entering the remote command.
    # shellcheck disable=SC2029
    # -n prevents SSH from consuming the remaining Terraform inventory on the
    # while loop's stdin after the first guest.
    guest_key=$(ssh -n -o BatchMode=yes -o StrictHostKeyChecking=yes \
      "$pve_user@$pve_address" \
      qm guest exec "$vm_id" -- cat /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null |
      jq -r 'select(.exited == 1 and .exitcode == 0) | .["out-data"] // empty' 2>/dev/null || true)
    valid_ed25519_public_key "$guest_key" && break
    sleep 5
  done
  valid_ed25519_public_key "$guest_key" || {
    printf 'Could not obtain the SSH host key for %s (VM %s).\n' "$name" "$vm_id" >&2
    exit 69
  }
  printf '%s %s\n' "$address" "$guest_key" >>"$temporary_known_hosts"
done < <(jq -r 'to_entries[] | [.value.address, (.value.vm_id | tostring), .key] | @tsv' <<<"$inventory")

mv "$temporary_known_hosts" "$known_hosts"

jq -n \
  --argjson inventory "$inventory" \
  --arg known_hosts "$known_hosts" '
  def host($name): {($name): {
    ansible_host: $inventory[$name].address,
    chaos_role: $inventory[$name].role
  }};
  {
    all: {
      vars: {
        ansible_user: "updatedc",
        ansible_ssh_common_args: ("-o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + $known_hosts),
        ansible_ssh_private_key_file: "{{ lookup(\"env\", \"UPDATEDC_CHAOS_SSH_KEY\") }}"
      },
      children: {
        chaos_cluster: {children: {k3s_server: {}, k3s_agents: {}}},
        k3s_server: {hosts: host("updatedc-chaos-control")},
        k3s_agents: {hosts:
          (host("updatedc-chaos-storage") + host("updatedc-chaos-agent-a") + host("updatedc-chaos-agent-b"))
        },
        chaos_storage: {hosts: host("updatedc-chaos-storage")},
        chaos_agents: {hosts: (host("updatedc-chaos-agent-a") + host("updatedc-chaos-agent-b"))}
      }
    }
  }' >"$temporary_inventory"

jq -e '(.all.children.k3s_server.hosts | length) == 1 and
       (.all.children.k3s_agents.hosts | length) == 3' "$temporary_inventory" >/dev/null
mv "$temporary_inventory" "$state_dir/inventory.json"
trap - EXIT
printf 'Wrote host-key-pinned inventory to %s\n' "$state_dir/inventory.json"

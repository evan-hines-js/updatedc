variable "proxmox_endpoint" {
  description = "Proxmox API endpoint."
  type        = string
  default     = "https://10.0.0.206:8006/"

  validation {
    condition     = can(regex("^https://[^/]+(?::[0-9]+)?/$", var.proxmox_endpoint))
    error_message = "proxmox_endpoint must be an HTTPS origin with a trailing slash."
  }
}

variable "proxmox_api_token" {
  description = "Least-privilege API token supplied through TF_VAR_proxmox_api_token."
  type        = string
  sensitive   = true
}

variable "proxmox_insecure" {
  description = "Permit the isolated lab's private Proxmox certificate."
  type        = bool
  default     = true
}

variable "proxmox_node_name" {
  type    = string
  default = "poweredge-md"
}

variable "proxmox_node_address" {
  type    = string
  default = "10.0.0.206"
}

variable "proxmox_ssh_username" {
  type    = string
  default = "root"
}

variable "proxmox_ssh_private_key" {
  description = "Private key bytes for provider operations on the Proxmox node."
  type        = string
  sensitive   = true
}

variable "datastore_id" {
  type    = string
  default = "local-lvm"
}

variable "image_datastore_id" {
  type    = string
  default = "local"
}

variable "guest_image_file_id" {
  description = "Existing checksum-verified Proxmox cloud-image volume."
  type        = string
  default     = "local:iso/ubuntu-24.04-server-cloudimg-amd64.img"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+:iso/[A-Za-z0-9._-]+$", var.guest_image_file_id))
    error_message = "guest_image_file_id must be a simple Proxmox ISO volume ID."
  }
}

variable "guest_image_sha256" {
  description = "Expected SHA-256 of guest_image_file_id, verified before planning."
  type        = string
  default     = "d1940f7d69d343355e183dff1e08a59852d32e7309baa7a4bad8365b11b005ac"

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.guest_image_sha256))
    error_message = "guest_image_sha256 must be exactly 64 lowercase hexadecimal characters."
  }
}

variable "bridge" {
  type    = string
  default = "vmbr0"
}

variable "gateway" {
  type    = string
  default = "10.0.0.1"
}

variable "dns_servers" {
  type    = list(string)
  default = ["10.0.0.1"]
}

variable "network_prefix" {
  type    = number
  default = 24

  validation {
    condition     = var.network_prefix >= 16 && var.network_prefix <= 30
    error_message = "network_prefix must be between 16 and 30."
  }
}

variable "ssh_username" {
  type    = string
  default = "updatedc"
}

variable "ssh_public_keys" {
  description = "Guest SSH keys, derived by deploy.sh from the configured private key."
  type        = list(string)
  sensitive   = true

  validation {
    condition     = length(var.ssh_public_keys) == 1 && startswith(var.ssh_public_keys[0], "ssh-")
    error_message = "Exactly one OpenSSH public key is required."
  }
}

variable "vm_addresses" {
  type = map(string)
  default = {
    updatedc-chaos-control = "10.0.0.250"
    updatedc-chaos-storage = "10.0.0.251"
    updatedc-chaos-agent-a = "10.0.0.252"
    updatedc-chaos-agent-b = "10.0.0.253"
  }

  validation {
    condition = toset(keys(var.vm_addresses)) == toset([
      "updatedc-chaos-control",
      "updatedc-chaos-storage",
      "updatedc-chaos-agent-a",
      "updatedc-chaos-agent-b"
    ])
    error_message = "vm_addresses must contain exactly the four chaos-lab VM names."
  }

  validation {
    condition     = length(distinct(values(var.vm_addresses))) == 4
    error_message = "Every chaos-lab VM needs a unique address."
  }

  validation {
    condition     = alltrue([for address in values(var.vm_addresses) : can(cidrnetmask("${address}/32"))])
    error_message = "Every chaos-lab address must be valid IPv4."
  }
}

variable "vm_ids" {
  type = map(number)
  default = {
    updatedc-chaos-control = 300
    updatedc-chaos-storage = 301
    updatedc-chaos-agent-a = 302
    updatedc-chaos-agent-b = 303
  }

  validation {
    condition     = toset(keys(var.vm_ids)) == toset(keys(var.vm_addresses))
    error_message = "vm_ids and vm_addresses must describe the same four VMs."
  }

  validation {
    condition     = length(distinct(values(var.vm_ids))) == 4
    error_message = "Every chaos-lab VM needs a unique VM ID."
  }
}

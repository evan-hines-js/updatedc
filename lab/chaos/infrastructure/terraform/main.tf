provider "proxmox" {
  endpoint  = var.proxmox_endpoint
  api_token = var.proxmox_api_token
  insecure  = var.proxmox_insecure

  ssh {
    agent       = false
    private_key = var.proxmox_ssh_private_key
    username    = var.proxmox_ssh_username

    node {
      name    = var.proxmox_node_name
      address = var.proxmox_node_address
    }
  }
}

locals {
  vm_topology = {
    updatedc-chaos-control = { role = "control", vm_id = var.vm_ids["updatedc-chaos-control"], cores = 4, memory = 8192, disk = 30 }
    updatedc-chaos-storage = { role = "storage", vm_id = var.vm_ids["updatedc-chaos-storage"], cores = 4, memory = 6144, disk = 30 }
    updatedc-chaos-agent-a = { role = "agent-a", vm_id = var.vm_ids["updatedc-chaos-agent-a"], cores = 4, memory = 4096, disk = 25 }
    updatedc-chaos-agent-b = { role = "agent-b", vm_id = var.vm_ids["updatedc-chaos-agent-b"], cores = 4, memory = 4096, disk = 25 }
  }
}

resource "proxmox_virtual_environment_file" "cloud_config" {
  for_each     = local.vm_topology
  content_type = "snippets"
  datastore_id = var.image_datastore_id
  node_name    = var.proxmox_node_name

  source_raw {
    file_name = "${each.key}-cloud-config.yaml"
    data = "#cloud-config\n${yamlencode({
      package_update = true
      packages       = ["qemu-guest-agent"]
      users = [{
        name                = var.ssh_username
        groups              = "sudo"
        shell               = "/bin/bash"
        sudo                = "ALL=(ALL) NOPASSWD:ALL"
        ssh_authorized_keys = var.ssh_public_keys
      }]
      runcmd        = [["systemctl", "enable", "--now", "qemu-guest-agent"]]
      ssh_pwauth    = false
      disable_root  = true
      final_message = "updatec chaos lab cloud-init complete"
    })}"
  }
}

resource "proxmox_virtual_environment_vm" "chaos" {
  for_each = local.vm_topology

  lifecycle {
    # Cloud-init is first-boot-only. Replacing a snippet must replace its VM;
    # an in-place update would claim success while leaving the old guest state.
    replace_triggered_by = [proxmox_virtual_environment_file.cloud_config[each.key]]

    precondition {
      condition     = cidrcontains("${var.gateway}/${var.network_prefix}", var.vm_addresses[each.key])
      error_message = "${each.key}'s address must belong to the configured gateway subnet."
    }

    precondition {
      condition = (
        var.vm_addresses[each.key] != var.gateway &&
        var.vm_addresses[each.key] != cidrhost("${var.gateway}/${var.network_prefix}", 0) &&
        var.vm_addresses[each.key] != cidrhost("${var.gateway}/${var.network_prefix}", -1)
      )
      error_message = "${each.key} must not use the gateway, network, or broadcast address."
    }
  }

  name          = each.key
  description   = "updatec real fault-injection lab: ${each.value.role}"
  node_name     = var.proxmox_node_name
  vm_id         = each.value.vm_id
  tags          = ["updatedc-chaos", "managed-by-terraform", each.value.role]
  on_boot       = false
  started       = true
  scsi_hardware = "virtio-scsi-single"

  agent {
    enabled = true
    timeout = "2m"
  }

  cpu {
    cores = each.value.cores
    type  = "host"
  }

  memory { dedicated = each.value.memory }

  disk {
    datastore_id = var.datastore_id
    file_id      = var.guest_image_file_id
    interface    = "scsi0"
    iothread     = true
    discard      = "on"
    size         = each.value.disk
  }

  network_device {
    bridge   = var.bridge
    firewall = false
    model    = "virtio"
  }

  initialization {
    datastore_id      = var.datastore_id
    user_data_file_id = proxmox_virtual_environment_file.cloud_config[each.key].id

    dns { servers = var.dns_servers }

    ip_config {
      ipv4 {
        address = "${var.vm_addresses[each.key]}/${var.network_prefix}"
        gateway = var.gateway
      }
    }
  }

  operating_system { type = "l26" }
  serial_device {}
}

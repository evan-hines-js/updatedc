output "inventory" {
  description = "Stable VM identity consumed by the Ansible stage."
  value = {
    for name, vm in proxmox_virtual_environment_vm.chaos : name => {
      address = var.vm_addresses[name]
      node    = var.proxmox_node_name
      role    = local.vm_topology[name].role
      vm_id   = vm.vm_id
    }
  }
}

output "proxmox_host" {
  value = {
    name    = var.proxmox_node_name
    address = var.proxmox_node_address
    user    = var.proxmox_ssh_username
  }
}

output "lab_subnet" {
  value = cidrsubnet("${var.gateway}/${var.network_prefix}", 0, 0)
}

output "guest_image" {
  value = {
    file_id = var.guest_image_file_id
    sha256  = var.guest_image_sha256
  }
}

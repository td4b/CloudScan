# QEMU VERSION
# UBUNTU / AUTOINSTALL

packer {
  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "iso_url" {
  default = "/Users/thomaswest/Downloads/ubuntu-22.04.5-live-server-amd64.iso"
}

variable "iso_checksum" {
  default = "sha256:9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0"
}

variable "image_name" {
  default = "ubuntu-packer.qcow2"
}

variable "output_directory" {
  default = "/Users/thomaswest/Downloads/Ubuntu-22.04-Build"
}

source "qemu" "ubuntu" {
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  vm_name          = var.image_name
  output_directory = var.output_directory

  accelerator      = "hvf" # Hypervisor.framework on macOS
  headless         = false  # Optional, for no display
  display          = "cocoa" # Use "none" for headless or "cocoa" for macOS UI
  memory           = 4172
  cpus             = 2
  disk_size        = 10000 # in MB
  disk_interface   = "virtio"
  disk_image       = false
  format           = "qcow2"
  ssh_username     = "ubuntu"
  ssh_private_key_file = "/Users/thomaswest/.ssh/packer_key"
  ssh_timeout      = "20m"
  shutdown_command = "sudo shutdown -P now"

  boot_wait = "5s"
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz --- autoinstall ds=\"nocloud-net;seedfrom=http://{{.HTTPIP}}:{{.HTTPPort}}/\"",
    "<enter><wait>",
    "initrd /casper/initrd",
    "<enter><wait>",
    "boot",
    "<enter>"
  ]

  http_directory = "http"
}

build {
  sources = ["source.qemu.ubuntu"]

  # Enable serial console for telnet to work correctly.
  provisioner "shell" {
    inline = [
      <<-EOF
        #!/bin/bash
        mkdir /home/ubuntu/agent
        sudo sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"/' /etc/default/grub
        echo 'GRUB_TERMINAL=serial' | sudo tee -a /etc/default/grub
        sudo update-grub
        sudo systemctl enable serial-getty@ttyS0.service
        sudo systemctl start serial-getty@ttyS0.service
      EOF
    ]
  }

  provisioner "file" {
    source      = "./Project/agent/arp_capture.o"
    destination = "/home/ubuntu/agent/arp_capture.o"
  }

  provisioner "file" {
    source      = "./Project/agent/main"
    destination = "/home/ubuntu/agent/main"
  }
}

# VMWARE VERSION

# packer {
#   required_plugins {
#     virtualbox = {
#       version = ">= 1.0.0"
#       source  = "github.com/hashicorp/virtualbox"
#     }
#   }
# }

# variable "iso_url" {
#   default = "/Users/thomaswest/Downloads/ubuntu-22.04.5-live-server-amd64.iso"
# }

# variable "iso_checksum" {
#   default = "sha256:9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a140635434a46aa98b0"
# }

# variable "vm_name" {
#   default = "ubuntu-packer"
# }

# source "vmware-iso" "ubuntu" {
#   vm_name            = "cloudscan-agent"
#   guest_os_type      = "ubuntu-64"
#   version            = "16"
#   headless           = false
#   memory             = 4172
#   cpus               = 2
#   cores              = 2
#   disk_size          = 50000
#   sound              = true
#   disk_type_id       = 0
#   iso_urls           = ["file:/Users/thomaswest/Downloads/ubuntu-22.04.5-live-server-amd64.iso"]
#   iso_checksum       = var.iso_checksum
#   iso_target_path    = "/Users/thomaswest/Downloads"
#   output_directory   = "/Users/thomaswest/Downloads/Ubuntu-22.04-Build"
#   snapshot_name      = "clean"
#   http_directory     = "http"
#   ssh_username       = "ubuntu"
#   ssh_private_key_file = "~/.ssh/packer_key"
#   ssh_timeout        = "20m"
#   shutdown_command   = "sudo shutdown -P now"

#   boot_wait = "5s"
#   boot_command = [
#     "c<wait>",
#     "linux /casper/vmlinuz --- autoinstall ds=\"nocloud-net;seedfrom=http://{{.HTTPIP}}:{{.HTTPPort}}/\"",
#     "<enter><wait>",
#     "initrd /casper/initrd",
#     "<enter><wait>",
#     "boot",
#     "<enter>"
#   ]
# }

# build {
#   sources = ["source.vmware-iso.ubuntu"]

#   provisioner "shell" {
#     inline = [
#       "mkdir /home/ubuntu/agent",
#     ]
#   }

#   provisioner "file" {
#     source      = "./Project/agent/arp_capture.o"
#     destination = "/home/ubuntu/agent/arp_capture.o"
#   }

#   provisioner "file" {
#     source      = "./Project/agent/main"
#     destination = "/home/ubuntu/agent/main"
#   }


# }

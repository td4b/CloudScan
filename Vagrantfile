Vagrant.configure("2") do |config|
  # Define the VM box
  config.vm.box = "bento/ubuntu-22.04" # Replace with desired Linux box

  # Use a public network (bridged mode)
  config.vm.network "public_network", bridge: "en0: Wi-Fi" # Replace with your network adapter name

  # Copy all the project folders to the VM.
  config.vm.synced_folder "./Project", "/home/vagrant/CloudScan", type: "nfs", mount_options: ["tcp"]

  # Configure resources for VMware Fusion
  config.vm.provider "vmware_fusion" do |vf|
    vf.memory = 8024 # Adjust memory as needed
    vf.cpus = 4      # Adjust CPU count as needed
  end

  # Install Devbox and run provisioning commands
  config.vm.provision "shell", inline: <<-SHELL
    # Update system packages
    sudo apt-get update -y
    sudo apt-get install -y curl libpcap-dev net-tools libbpf-dev
    sudo apt-get install -y linux-headers-$(uname -r) linux-headers-generic linux-libc-dev clang llvm libelf-dev gcc-multilib

    # install k3s 
    curl -sfL https://get.k3s.io | sh -

    # Copy kube config to default path.
    sudo mkdir /home/vagrant/.kube
    sudo cat /dev/null | sudo tee /home/vagrant/.kube/config > /dev/null
    sudo cat /etc/rancher/k3s/k3s.yaml | sudo tee /home/vagrant/.kube/config > /dev/null
    sudo chown -R vagrant:vagrant /home/vagrant/.kube
    sudo chmod 600 /home/vagrant/.kube/config

    # Install Devbox
    curl -fsSL https://get.jetify.com/devbox | bash -s -- -f

    # Ensure Devbox is added to PATH
    export PATH="$HOME/.devbox/bin:$PATH"

    # ensure devbox can be run by vagrant user
    chown vagrant:vagrant /usr/local/bin/devbox

    # Install Nix if it is missing.
    yes "" | devbox shell
  SHELL
end

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "5.13.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id                 = "00000000-0000-0000-0000-000000000000"
  tenant_id                       = "00000000-0000-0000-0000-000000000000"
  client_id                       = "00000000-0000-0000-0000-000000000000"
  client_secret                   = "offline-plan-probe-not-a-secret"
  resource_provider_registrations = "none"
  use_cli                         = false
  use_msi                         = false
  use_oidc                        = false
}

resource "azurerm_resource_group" "rg" {
  name     = "probe"
  location = "francecentral"
}

resource "azurerm_virtual_network" "vn" {
  name                = "probe"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.1.0.0/16"]
}

resource "azurerm_subnet" "vms" {
  name                 = "vms"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vn.name
  address_prefixes     = ["10.1.1.0/24"]
}

resource "azurerm_network_interface" "nic" {
  name                = "probe"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vms.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                            = "probe"
  location                        = azurerm_resource_group.rg.location
  resource_group_name             = azurerm_resource_group.rg.name
  size                            = "Standard_B2s"
  admin_username                  = "rempart"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.nic.id]
  admin_ssh_key {
    username   = "rempart"
    public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCGcCFdIUlPj42btbQNCC17p1nfCcU4qlT4czFV9sfogFSNN63G+y/QvzIA+95A61xVWElrYrw4dQy3kj3i66kCoMS8KpFsSxFbUHayMkVANFa+BCn8mKyzh7j0ILLUbL86lapZ7t4TzIMp8ISjNLpiPtZeCZZEhJZDauNwmpsukGBY9mo2slUPqQxGoMXirF/5ZxGdDC/KFDAwRBnUYQ7NsJQBH3ry3qjM2J+J33MgbaJwCSszAlOmYtL1mo1sdhAq9ykursNWfPRIFxJjRwKD/WMhTxPLm5LRMPvrI778mSdy5eqWrpOnCqW0vYa/Y0GTgk4eCbe85vyGVoZdosrBSo4PT4T2JRYnxFHS1StWPEQQefCpTfOFSl+D+VEqiuxuO45VtYAF3axy6IIkA7oxPkA1pAGr2ixrND5fI0WuVUd9/MUXqVUFntTtqN/rlp4FY9TGWnKxijTqQP+KCukEvFV9vYzIX92Wgnf46s/+0QMfP3J+n/QtRQppPxa8J6s= probe"
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}

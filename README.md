# Azure Firewall lab with explicit proxy

This creates a resource group, a hub vnet with an Azure firewall with explicit proxy set and a spoke vnet peered to the hub vnet. A storage account is also created to host .PAC file for the firewall to access. This creates a log analytics workspace and diagnostic settings for the firewall logs. Also creates Windows VM's in the default subnets with your public ip added to an NSG allowing RDP access and the PAC file set for the proxy. This also creates a logic app that will delete the resource group in 24hrs. You'll be prompted for the resource group name, location where you want the resources created, your public ip and username and password to use for the VM's.

The topology will look something like this: 
![image](https://github.com/quiveringbacon/azfwlab-explicitproxy/assets/128983862/62ecc709-fab1-471c-9084-6859121b1a77)

You can run Terraform right from the Azure cloud shell by cloning this git repository with "git clone https://github.com/quiveringbacon/azfwlab-explicitproxy.git ./terraform".

Then, "cd terraform" then, "terraform init" and finally "terraform apply -auto-approve" to deploy.

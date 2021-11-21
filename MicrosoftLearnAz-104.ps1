#Create a VM
az vm create \
  --resource-group learn-d2bb8ebf-76ab-4730-9b4c-867b331fbf24 \
  --location westus \
  --name SampleVM \
  --image UbuntuLTS \
  --admin-username azureuser \
  --generate-ssh-keys \
  --verbose

#/bin/bash

echo Running Playbook gcp_create_instances.yml
ansible-playbook --vault-password-file ../../.vault-pass.txt -i gcp_inventory.gcp.yml gcp_create_instances.yml

echo Running Playbook gcp_reset_windows_passwords.yml
ansible-playbook --vault-password-file ../../.vault-pass.txt -i gcp_inventory.gcp.yml gcp_reset_windows_passwords.yml

echo Running Playbook gcp_dsa_facter_install.yml
ansible-playbook --vault-password-file ../../.vault-pass.txt -i gcp_inventory.gcp.yml gcp_dsa_facter_install.yml

echo Sleeping for 5 minutes
sleep 300

echo Running Playbook gcp_terminate.yml
ansible-playbook --vault-password-file ../../.vault-pass.txt -i gcp_inventory.gcp.yml gcp_terminate.yml

#/bin/bash
ansible-playbook --vault-password-file ../../.vault-pass.txt -i gcp_inventory.gcp.yml gcp_create_instances.yml
ansible-playbook --vault-password-file ../../.vault-pass.txt -i gcp_inventory.gcp.yml gcp_reset_windows_password.yml

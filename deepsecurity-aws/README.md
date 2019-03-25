ansible-playbook --vault-password-file ../../.vault-pass.txt -i ec2.py ec2_create_instances.yml

ansible-playbook --vault-password-file ../../.vault-pass.txt -i ec2.py -u ubuntu ec2_ds_agent_facter_install.yml

ansible-playbook --vault-password-file ../../.vault-pass.txt -i ec2.py -u ubuntu ec2_wordpress_db_install_set.yml

ansible-playbook --vault-password-file ../../.vault-pass.txt -i ec2.py -u ubuntu ec2_wordpress_db_config.yml

ansible-playbook --vault-password-file ../../.vault-pass.txt -i ec2.py -u ubuntu ec2_ds_recommendation_scan.yml

ansible-playbook --vault-password-file ../../.vault-pass.txt -i ec2.py -u ubuntu ec2_terminate.yml


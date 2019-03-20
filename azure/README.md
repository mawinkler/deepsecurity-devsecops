ansible-playbook --ask-vault-pass -i azure_rm.py az_create_instances.yml

ssh-keygen -f /home/ansible/.ssh/known_hosts -R testvm001-IP

ssh-keygen -f /home/ansible/.ssh/known_hosts -R testvm002-IP

ansible-playbook --ask-vault-pass -i azure_rm.py az_deploy_dsagent.yml

ansible-playbook --ask-vault-pass -i azure_rm.py az_set_policy.yml

ansible-playbook --ask-vault-pass -i azure_rm.py az_deploy_custom_fact.yml

ansible -i azure_rm.py testvm001 -m setup -a "filter=ansible_local" -b -K

ansible -i azure_rm.py testvm002 -m setup -a "filter=ansible_local"

ansible-playbook --ask-vault-pass -i azure_rm.py az_deploy_apache.yml

ansible -i azure_rm.py testvm001 -m setup -a "filter=ansible_local" -b -K

ansible -i azure_rm.py testvm002 -m setup -a "filter=ansible_local"

ansible-playbook -i azure_rm.py az_terminate.yml

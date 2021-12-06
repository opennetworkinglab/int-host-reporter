# SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
#
# SPDX-License-Identifier: Apache-2.0

vagrant:
	vagrant up

cluster:
	ansible-playbook playbook.kubecluster.yml -i inventory.ini

destroy:
	vagrant destroy

clean:
	ansible-playbook playbook.deletecluster.yml -i inventory.ini

# Copyright 2021-present Open Networking Foundation
# SPDX-License-Identifier: Apache-2.0

sudo apt-get -y upgrade
sudo apt-get update

# Install python3 for ansible
sudo apt-get -y install python3 python3-pip python3-apt net-tools

# Disable swap
swapoff -a

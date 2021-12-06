<!--
Copyright 2021-present Open Networking Foundation
SPDX-License-Identifier: Apache-2.0
-->

# CI test infra deployment

This sub-directory contains Vagrant scripts to build a simple Kubernetes cluster (1 master, 1 worker + tester VM) that is used to run CI integration tests.

The scripts are based on [Kubeclust](https://github.com/kosyfrances/kubeclust).

## Build CI test infra

The scripts use `vagrant` with `libvirt` provider to boostrap VMs. Make sure you have both installed.

Ansible is used to install Kubernetes cluster on the VMs. Install the required software first:

```bash
$ pip install -r requirements.txt
```

To create Virtual Machines:

```bash
$ make vagrant
```

To install Kubernetes cluster:

```bash
$ make cluster
```

## Clean up

To remove Kubernetes cluster from VMs:

```bash
$ make clean
```

To destroy the entire Vagrant setup:

```bash
$ make destroy
```


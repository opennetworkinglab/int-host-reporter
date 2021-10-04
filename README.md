# INT Host Reporter

The In-Band Network Telemetry (INT) standard is a network telemetry solution providing an in-depth, per-packet network visibility. 
So far, the INT standard has been mainly implemented by the network switches (this implementation is somewhere referred as "switch-INT"). 

The INT Host Reporter is the implementation of the "host-INT" approach - the concept of extending the In-Band Network Telemetry (INT)
support to the end hosts. 
The INT Host Reporter is tightly integrated with Kubernetes and generates an INT report (flow or drop report) for each packet being sent between (virtual) network interfaces managed by the Kubernetes Container Network Interface (CNI). 
The INT reports are furhter sent to the INT collector that gathers INT reports from different network devices (e.g. switches, hosts) and shows the end-to-end network statistics.
This enables observing E2E network flows traversing the Kubernetes cluster (e.g. Pod-to-Pod communication or packets to/from Kubernetes Services).

## Overview

`INT Host Reporter` implements the "host-INT" approach by using a combination of the eBPF code running in the Linux kernel 
and a Go application running as an userspace agent. The diagram below shows the high-level design of the host-INT solution, which is independent of the Kubernetes CNI being used.

![Design](docs/static/images/design.png?raw=true "High-level design of CNI-independent host-INT")

As depicted in the diagram, the system consists of two pieces:

- the **INT-aware eBPF programs** are attached to both TC Ingress and TC Egress hooks. The ingress eBPF program
does a basic packet pre-processing and collects ingress metadata that is further stored in a shared BPF map.
  The egress eBPF program reads the per-packet metadata and generates a data plane report by pushing an event to the 
  `BPF_PERF_EVENT_ARRAY` map .
- the **INT Host Reporter** application listens to the events from the `BPF_PERF_EVENT_ARRAY` map, converts
the data plane reports into INT reports and sends the INT reports to the INT collector. 
  
As mentioned before, the INT Host Reporter works in the CNI-independent fashion, so the target goal is to enable using INT Host Reporter with _any_ Kubernetes CNI. 
So far, we have tested the INT Host Reporter with [Calico](https://docs.projectcalico.org/getting-started/kubernetes/) and [Cilium](https://cilium.io/) and DeepInsight from Intel as an INT collector. 

## Building INT Host Reporter

To build the INT Host Reporter image from scratch run the below command from the main directory:

```bash
$ docker build -t <IMAGE-NAME>:<TAG> .
```

## Downloading INT Host Reporter image

Alternatively, the Docker image of INT Host Reporter can be downloaded from the Aether registry.

```bash
$ docker pull registry.aetherproject.org/tost/int-host-reporter:latest
```

## Deployment guide

### Requirements

- Kernel version v5.11 or higher. 
- `CAP_SYS_ADMIN` privileges with access to the host network (`hostNetwork: true`).
- Access to the eBPF filesystem (`/sys/fs/bpf`).

### Install the K8s cluster

The installation of a Kubernetes cluster is basically out of scope of this document. 
You should follow the instructions to deploy the Kubernetes cluster using the installer of your choice ([see Kubernetes documentation](https://kubernetes.io/docs/setup/)).

### Create K8s secret

We use private `registry.aetherproject.org` registry to pull the `int-host-reporter` image. To make the K8s deployment working
you firstly have to set up a K8s secret.

- Log in to `registry.aetherproject.org` using `docker login`. Your password will be stored unencrypted under `~/.docker/config.json`.
- base64 encode your password:

```
$ cat ~/.docker/config.json | base64 -w0
```

- Copy the output and create the `aether-secret.yaml` file.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: aetherregistrysecret
data:
  .dockerconfigjson: <base-64-encoded-json-here>
type: kubernetes.io/dockerconfigjson
```

- Create the K8s secret based on the `aether-secret.yaml` file.

`$ kubectl create -n kube-system -f aether-secret.yaml`

### Deploy INT Host Reporter

Edit `deployment/kubernetes/inthostreporter.yaml` and configure the following variables:

- `CNI` should define the Kubernetes CNI being used for the cluster. We currently support the following values: `cilium`, `calico-ebpf`, `calico-iptables`.
- `COLLECTOR` should point to the address of the INT collector (e.g. 192.168.50.99:32766).
- `DATA_INTERFACE` should be set to the name of physical interface that has the `status.hostIP` assigned. 
  For instance, if Kubernetes API server is advertised on `192.168.99.20`, the data interface is the interface that has this IP address assigned.

Next, prepare the INT watchlist file (modify `configs/watchlist.yaml` if needed) and deploy it as ConfigMap. 

`$ kubectl create -n kube-system configmap watchlist-conf --from-file=./configs/watchlist.yaml`

Then, run the below command to deploy the INT Host Reporter.

`$ kubectl apply -f deployment/kubernetes/inthostreporter.yaml`

Verify that the `int-host-reporter` is in the Running state on each node:

```bash
$ kubectl get pods --all-namespaces -o wide
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE     IP              NODE         NOMINATED NODE   READINESS GATES
kube-system   int-host-reporter-jpdl2                    1/1     Running   0          9m11s   10.79.233.238   worker2      <none>           <none>
kube-system   int-host-reporter-ljwvs                    1/1     Running   0          9m11s   10.68.235.172   worker1      <none>           <none>
kube-system   int-host-reporter-x48ps                    1/1     Running   0          9m11s   10.67.219.106   kubemaster   <none>           <none>
```

For the CNIs that we have tested, there are no CNI-specific configuration steps required for the INT Host Reporter to work properly.
Once the INT Host Reporter is successfully deployed, it should start sending INT reports to the collector. 

## Using INT Host Reporter with DeepInsight

If the INT Host Reporter has been successfully deployed, it will start generating and sending INT reports to the INT collector.
So far, the Host INT Reporter has been tested with DeepInsight (DI) - the INT collector provided by Intel. 
DeepInsight requires the additional configuration step to start visualizing network statistics.  

The additional configuration step is to upload the DI topology file - the JSON file that describes 
the topology of a network. In particular, the DI topology should have the following sections defined:

- `switches` - the list of switches in the network. In the case of host-INT, the virtual switch (CNI datapath) is also defined as the switch.
Thus, this section should contain each network switch plus all the hosts, where the Kubernetes is running on.
- `hosts` - the list of hosts in the network. In the case of host-INT, the `hosts` section should contain all servers attached to the network,
except those being used as K8s nodes.
- `subnets` - the list of subnets in the network. In the case of host-INT, it should contain the subnet used to interconnect Kubernetes nodes, as well as
the all the Pod subnets (the range of IP addresses, from which the Pod IPs are assigned from). Typically, a CNI will use a single IP subnet per Kubernetes worker,
  so there should be at least as many subnets defined as the number of Kubernetes workers.
- `links` - the list of links in the network. It represents links between 2 switches, between a switch and a host, or between a switch and a subnet -
the last way of representing a link is an abstraction introduced by DeepInsight and means that we can access a subnet via a given interface of a switch.
In the case of host-INT, Pods are not defined as `hosts`, but we use `subnet` to represent the group of Pods attached to the network. Therefore,
the `links` section should contain the links between a virtual switch and a Pod's subnet for each virtual interface configured on the Kubernetes node.

As a reference, we provide a sample DI topology file in in the `examples/deepinsight/` directory. The sample DI topology file is visualized below. The dashed lines
represents the abstraction of connections between switch and subnet. 

![The visualization of a sample DI topology](docs/static/images/di-topo.png?raw=true "The visualization of a sample DI topology")

However, building the DI topology file manually is time-consuming and error-prone. Therefore, we have created the `./di gen-topology` script
to automate this process. You can find the guide how to use this script in [the sdfabric-utils repository](https://github.com/opennetworkinglab/sdfabric-utils).

## Current limitations 

- Only IPv4 endpoints are supported.
- INT Host Reporter only supports UDP/TCP packets; ICMP packets are not reported.
- System flows (e.g. traffic between Kubernetes agents) are not reported.

# INT Host Reporter

`INT Host Reporter` is a Go application implementing the support for the In-Band Network Telemetry on the end hosts running Kubernetes.

`INT Host Reporter` leverages the modified Calico CNI and its eBPF dataplane as a network backend generating data plane reports.

![Design](docs/static/images/design.png?raw=true "High-level design of CNI-independent host-INT")

## Building INT Host Reporter

From the main directory:

```bash
$ docker build -t registry.aetherproject.org/tost/int-host-reporter:<TAG> .
```

## Deployment guide

### Install the K8s cluster

The installation of a Kubernetes cluster is basically out of scope of this document. 
You should follow the instructions to deploy the Kubernetes cluster using the installed of your choice (see Kubernetes documentation). 

However, we provide [the manual installation](./docs/k8s-cluster-installation.md) guide that can be used for the testing purpose. 

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

Edit `deployment/kubernetes/inthostreporter.yaml` and set the `COLLECTOR` variable pointing to the address of the INT collector.

Prepare the INT watchlist file (modify `configs/watchlist.yaml` if needed) and deploy it as ConfigMap. 

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

## Using INT Host Reporter with DeepInsight

The host-INT implementation has been tested with DeepInsight - the INT collector provided by Intel. 
We describe how to use DeepInsight to visualize reports provided by host-INT below. 



## TODOs 

- Only IPv4 is supported. 
- INT Host Reporter only supports UDP/TCP packets; ICMP packets are not reported.

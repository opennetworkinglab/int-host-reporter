# INT Host Reporter

`INT Host Reporter` is a Go application implementing the support for the In-Band Network Telemetry on the end hosts running Kubernetes.

`INT Host Reporter` leverages the modified Calico CNI and its eBPF dataplane as a network backend generating data plane reports.

## Deployment guide

### Install the ONF flavor of Calico CNI

TODO

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

`$ kubectl apply -f deployment/kubernetes/inthostreporter.yaml`

Verify that the `inthostreporter` is in the Running state on each node:

```bash
$ kubectl get pods --all-namespaces -o wide
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE     IP              NODE         NOMINATED NODE   READINESS GATES
kube-system   int-host-reporter-jpdl2                    1/1     Running   0          9m11s   10.79.233.238   worker2      <none>           <none>
kube-system   int-host-reporter-ljwvs                    1/1     Running   0          9m11s   10.68.235.172   worker1      <none>           <none>
kube-system   int-host-reporter-x48ps                    1/1     Running   0          9m11s   10.67.219.106   kubemaster   <none>           <none>
```

## Conclusions from PoC

- consider adding a `flow-id` field to the INT report to correlate pre-/post-NAT flows. Although the Calico datapath provides 
  `PreNATDestinationIP` and `PreNATDestinationPort` restoring an original flow may cause that we loose information about a given Pod.
  For example, there is a problem with a specific Pod, but the INT collector will see a report related to the K8s Service - 
  given the fact that we can have many (!) Pods under a single K8s Service it may cause troubleshooting really difficult.
  The ideal situation would be that we provide an original packet (pre- or post-NAT'ed, depending on the trace point) plus 
  the `flow-id`, so the INT collector can easily correlate packets. 

## TODOs 

- Only IPv4 is supported
- Currently, we generate an INT report for each packet. It might lead to the network overload. We may want to apply 
Bloom Filter or other solution to limit the number of INT reports.
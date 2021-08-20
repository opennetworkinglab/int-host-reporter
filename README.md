# INT Host Reporter

`INT Host Reporter` is a Go application implementing the support for the In-Band Network Telemetry on the end hosts running Kubernetes.

`INT Host Reporter` leverages the modified Calico CNI and its eBPF dataplane as a network backend generating data plane reports.

## Building INT Host Reporter

From the main directory:

```bash
$ ./scripts/compile-bpf.sh
$ docker build -t registry.aetherproject.org/tost/int-host-reporter:<TAG> .
```

## Deployment guide

### Install the K8s cluster

On each K8s node:

```bash
$ sudo apt-get update
$ sudo apt-get install -y containerd=1.3.3-0ubuntu2
$ sudo apt-get install -y docker.io=19.03.8-0ubuntu1.20.04.1
$ sudo usermod -aG docker $USER
$ sudo systemctl enable docker
$ sudo apt-get update
$ sudo apt-get install -y apt-transport-https ca-certificates curl
$ sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
$ echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
$ sudo apt-get update
$ sudo apt-get install -y kubelet kubeadm kubectl
$ sudo apt-mark hold kubelet kubeadm kubectl
```

Edit `kubelet` configuration (`/etc/systemd/system/kubelet.service.d/10-kubeadm.conf`) and add `--node-ip` as follows:

```
ExecStart=/usr/bin/kubelet --node-ip=<NODE-IP>  $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
```

Then, you need to reload `kubelet`:

```bash
$ sudo systemctl daemon-reload
$ sudo systemctl restart kubelet
```

On the K8s master node invoke:

```bash
$ sudo kubeadm init --pod-network-cidr=10.0.0.0/16 --apiserver-advertise-address=<NODE-IP>
```

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

Verify that the `inthostreporter` is in the Running state on each node:

```bash
$ kubectl get pods --all-namespaces -o wide
NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE     IP              NODE         NOMINATED NODE   READINESS GATES
kube-system   int-host-reporter-jpdl2                    1/1     Running   0          9m11s   10.79.233.238   worker2      <none>           <none>
kube-system   int-host-reporter-ljwvs                    1/1     Running   0          9m11s   10.68.235.172   worker1      <none>           <none>
kube-system   int-host-reporter-x48ps                    1/1     Running   0          9m11s   10.67.219.106   kubemaster   <none>           <none>
```

## Verify drop reports

The drop reasons specified by the Calico eBPF datapath are eBPF-specific (e.g. fail to adjust room during encapsulation). 
Thus, it is not straightforward to verify drop reports. The common case for packet drops is IP TTL < 0.
To verify drop reports we can simply generate UDP packets with IPv4 TTL = 0. Note that destination IPv4 address and UDP port 
must point to the K8s NodePort service.

```bash
$ sendp(Ether()/IP(dst="192.168.99.20",ttl=0)/UDP(dport=31584), iface="enp0s8")
```


## TODOs 

- Only IPv4 is supported
- Currently, we generate an INT report for each packet. It might lead to the network overload. We may want to apply 
Bloom Filter or other solution to limit the number of INT reports.
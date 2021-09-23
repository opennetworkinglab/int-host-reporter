# Manual installation of Kubernetes cluster 

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
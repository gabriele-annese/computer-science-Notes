---
tags:
  - k8s
  - etcdctl
---

`etcdctl` is a CLI tool using to interact with [ETCD](https://etcd.io/) . etcdctl can interact with ETCD server using 2 API version. 

Command supported by version 2
```bash
etcdctl backup
etcdctl cluster-health
etcdctl mk
etcdctl mkdir
etcdctl set
```

Command supported by version 3
```bash
etcdctl snapshot save
etcdctl endpoint health
etcdctl get
etcdctl put
```

To set the right version of API set the environment variable `ETCDCTL_API` command

```bash
export ETCDCTL_API=3
```


## Certificate

You must also specify the path to certificate files so that ETCDCTL can authenticate to the ETCD API Server. The certificate files are available in the etcd-master at the following path.

```bash
--cacert /etc/kubernetes/pki/etcd/ca.crt
--cert /etc/kubernetes/pki/etcd/server.crt
--key /etc/kubernetes/pki/etcd/server.key
```


Set certificate and certificate command
```bash
kubectl exec etcd-controlplane -n kube-system -- sh -c "ETCDCTL_API=3 etcdctl get / \
  --prefix --keys-only --limit=10 / \
  --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt \
  --key /etc/kubernetes/pki/etcd/server.key"
```

#flashcards/k8s/etcd

Quale tool in CLI si utilizza per interagire con ETCD? :: Si usa etcdctl
<!--SR:!fsrs,2026-09-16T06:22:22.730Z,8,8.2956,1,2,1,0,0,2026-09-08T06:22:22.730Z-->

Come si setta la versione corretta delle API per comunicare con etcd? 
?
Si utilizza la varibile d'ambinete `export ETCDCTL_API=3`

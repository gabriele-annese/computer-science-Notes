**Create an NGINX pod**
```bash
kubectl run nginx --image=nginx
```

**Generate POD Manifest YAML file (-o yaml). Don’t create it(–dry-run)**
```bash
kubectl run nginx --image=nginx --dry-run=client -o yaml
```

**Create a deployment**
```bash
kubectl create deployment --image=nginx nginx
```

**Generate Deployment YAML file (-o yaml). Don’t create it(–dry-run)**
```bash
kubectl create deployment --image=nginx nginx --dry-run=client -o yaml
```

**Generate Deployment YAML file (-o yaml). Don’t create it(–dry-run) and save it to a file.**
```bash
kubectl create deployment --image=nginx nginx --dry-run=client -o yaml > nginx-deployment.yaml
```

Make necessary changes to the file (for example, adding more replicas) and then create the deployment.

```bash
kubectl create -f nginx-deployment.yaml
```

In k8s version 1.19+, we can specify the –replicas option to create a deployment with 4 replicas.

```bash
kubectl create deployment --image=nginx nginx --replicas=4 --dry-run=client -o yaml > nginx-deployment.yaml
```

**List all api-resource type available on k8s**
```bash
kubectl api-resources
```

Example of output
```text
kubectl api-resources
NAME                                SHORTNAMES   APIVERSION                          NAMESPACED   KIND
bindings                                         v1                                  true         Binding
componentstatuses                   cs           v1                                  false        ComponentStatus
configmaps                          cm           v1                                  true         ConfigMap
endpoints                           ep           v1                                  true         Endpoints
events                              ev           v1                                  true         Event
limitranges                         limits       v1                                  true         LimitRange
namespaces                          ns           v1                                  false        Namespace
nodes                               no           v1                                  false        Node
persistentvolumeclaims              pvc          v1                                  true         PersistentVolumeClaim
persistentvolumes                   pv           v1                                  false        PersistentVolume
pods                                po           v1                                  true         Pod

.........
```

**Explain resource**
In k8s it's possible use the `explain` command to list all top level fields
```bash
kubectl explain pods
```

to list **all fields** run
```bash
kubectl explain pods --recursive
```

## Check cluster's component status

``` bash
kubectl get cs
# or
kubectl get componentstatuses
```

```bash
kubectl get pods -n kube-system
```

```bash
yq -p yaml -o json binding-object.yaml > binding.json
```

# Taint & Tolleration

```bash
kubectl taint nodes node01 spray=mortein:NoSchedule
```

```bash
k describe node/controlplane | grep Taints
```

Create a pod with toleration
```yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: bee
spec:
  containers:
    - image: nginx
      name: bee
  tolerations:
    - key: "spray"
      value: "mortein"
      effect: "NoSchedule"
      operator: "Equal"
```

Remove a Taint from node
```bash
kubectl taint nodes controlplane node-role.kubernetes.io/control-plane:NoSchedule-
```


```bash
kubectl get nodes/node01 -o json | jq -r '.metadata.labels'
```

to assign a label on node

```bash
kubectl label node/node01 color=blue
```

show labels
```bash
kubectl get nodes node01 --show-label
```

node affinity
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: blue
  name: blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: blue
  template:
    metadata:
      labels:
        app: blue
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                - key: color
                  operator: In
                  values:
                    - blue
      containers:
      - image: nginx
        name: nginx
```


operator exists

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: red
  name: red
spec:
  replicas: 2
  selector:
    matchLabels:
      app: red
  template:
    metadata:
      labels:
        app: red
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                - key: node-role.kubernetes.io/control-plane
                  operator: Exists
      containers:
      - image: nginx
        name: nginx
~                                                                                               
```

create a static pod 
```bash
kubectl run --restart=Never --image=busybox static-busybox --dry-run=client -o yaml --command -- sleep 1000 > /etc/kubernetes/manifests/static-busybox.yaml
```

## Challenge

### Delete a static pod on node01

Firs i jump into node01 system with ssh
```bash
ssh node01
```

kublet is the component that manage a static pod. To search the path where the manifest of the static pod are saved follow this step
```bash
ps aux | grep kubelet
```

take the path of the config in my case **/var/lib/kubelet/config.yaml** and search staticPod

```bash
node01 ~ ➜  cat /var/lib/kubelet/config.yaml | grep static
staticPodPath: /etc/just-to-mess-with-you
```

and voulà, now remove manifest of the static pod in question

```bash
node01 ~ ➜  ls /etc/just-to-mess-with-you/
greenbox.yaml

node01 ~ ➜  rm /etc/just-to-mess-with-you/greenbox.yaml
```

restart the kublet service
```bash
node01 ~ ➜  systemctl restart kubelet
```
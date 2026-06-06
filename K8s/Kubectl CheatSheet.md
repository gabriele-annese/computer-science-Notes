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


```yaml
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: high-priority
value: 100000
globalDefault: false
preemptionPolicy: PreemptLowerPriority
description: "This is a test"
```

a pod with priorty class
```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: pod
  name: high-prio-pod
spec:
  containers:
  - image: nginx
    name: high-prio-pod
  dnsPolicy: ClusterFirst
  restartPolicy: Always
  priorityClassName: high-priority
```

```bash
k get pods -o custom-columns="NAME:.metadata.name,PRIORITY:.spec.prior
ityClassName"
```
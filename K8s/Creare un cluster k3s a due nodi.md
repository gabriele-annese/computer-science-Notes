
una volta create le due vm
- ubuntu1 -> ip 10.10.0.11
- ubuntu2 -> ip 10.10.0.12

possiamo procedere con l'installazione di k3s.

Entriamo sulla prima macchina `ubuntu1`, per installarlo basta lanciare il seguente comando 
```bash
sudo curl -sfL https://get.k3s.io | sh -
```

per controllare che k3s stia runnando 
```bash
systemctl status k3s
```

Per connetterci dalla nostra macchina al cluster k3s bisogan recuperare le "credenziali". Le credenziali di k3s si trovano sotto la path

```bash
sudo cat /etc/rancher/k3s/k3s.yaml 
```

queste credenziali possono essere copiate in un file .yaml e utilizzate per esempio con un comando che utilizza il flag `--kubeconfig`
```bash
kubectl get nodes --kubeconfig pippo.yaml
```

oppure puo essere salvato nel file `~/.kube/config`, utili quando si hanno multi config per diversi cluster.

> Attenzione
> In entrambi i casi i valori di `server` nel config vanno cambiati perche' altrimenti puntano internamente (127.0.0.1:6443)


## Join di nodo al cluster

Presupponiamo che volessimo aggiungere al nostro cluster un nodo per farlo entriamo prima nuovamente nella VM `ubuntu1` (la master) e recuperiamo il token di accesso 
```bash
sudo cat /var/lib/rancher/k3s/server/token
```

recuperato il token entriamo nella `ubunutu2` e qui dovremmo creare due variabili d'ambiente
- K3S_URL: Indica l'URL del server k3s (`ubuntu1`)
- K3S_TOKEN: E' il token di accesso al server k3s
```bash
export K3S_URL=https://10.10.0.11:6443
export K3S_TOKEN=K10878395ffeba84659398ddf03406b7659ad3eea1d8fe52a328ed66c8e4e3a438d::server:aff5869a56a02d6d7d80144e8c0b5233
```

una volta fatto bastera rilanciare il comando 
```bash
sudo cat /var/lib/rancher/k3s/server/token
```

se tutto e' andato a buon fine vedreno che questa volta lo script avra creato il service `k3s-agent.service` perche appunto questa macchina sara l'agnete

```bash
systemctl status k3s-agent
```

se ora tornaimo sulla macchina principale e lanciamo il comando

```bash
 kubectl get nodes
NAME      STATUS   ROLES           AGE   VERSION
ubuntu1   Ready    control-plane   33m   v1.36.5+k3s1
ubuntu2   Ready    <none>          25m   v1.36.5+k3s1
```

vedremo che ci satanno due nodi.

Per aggiungere il ruolo al node basta lanciare il comando 
```bash 
kubectl label node ubuntu2 kubernetes.io/role=worker
node/ubuntu2 labeled

kubectl get nodes
NAME      STATUS   ROLES           AGE   VERSION
ubuntu1   Ready    control-plane   37m   v1.36.5+k3s1
ubuntu2   Ready    worker          28m   v1.36.5+k3s1
```

##  ControlPlain senza 

Se si vuole utilizzare il nodo `Control plain` solo come schedulatore e non vogliamo che nessun pod venga schedulato su di esso possiamo utilizzare il `taint`

Per aggiungere il taint 
```bash
kubectl taint node ubuntu1 node.role.kubernetes.io/control-plane:NoSchedule

kubectl describe node ubuntu1 | grep -i taint
Taints:             node.role.kubernetes.io/control-plane:NoSchedule
```

per rimovere il taint 
```bash
kubectl taint node ubuntu1 node.role.kubernetes.io/control-plane:NoSchedule-


kubectl describe node ubuntu1 | grep -i taint
Taints:             <none>
```


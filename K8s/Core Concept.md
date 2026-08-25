---
tags:
  - k8s
---

# Core Concepts

## Pod

Il Pod è l'unità di deployment minima: uno o più container che
condividono network namespace e volumi.

#flashcards/k8s/core

Qual è l'unità di scheduling minima in Kubernetes? :: Il Pod, non il containerR
<!--SR:!fsrs,2026-08-25T21:28:43.488Z,0,2.3065,2.11810397,1,1,0,1,2026-08-25T21:18:43.488Z-->

Due container nello stesso Pod comunicano tra loro via ==localhost==,
perché condividono lo stesso network namespace.
<!--SR:!fsrs,2026-08-25T21:29:06.401Z,0,2.3065,2.11810397,1,1,0,1,2026-08-25T21:19:06.401Z-->

Cosa distingue un initContainer da un container normale?
?
Gira a completamento prima che partano i container principali, e in
sequenza se ce n'è più di uno. Se fallisce, il Pod viene riavviato
secondo la restartPolicy.
<!--SR:!fsrs,2026-08-25T21:28:51.794Z,0,2.3065,2.11810397,1,1,0,1,2026-08-25T21:18:51.794Z-->

Comando per vedere i container di un Pod
?
```kubectl get pod <nome> -o jsonpath='{.spec.containers[*].name}'```

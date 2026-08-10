
Scan UPD services between ports 4995 and 5005
```bash
sudo nmap -sU -p 4995-5005 TARGET
```


service detection
```bash
sudo nmap -sU -sV -p 5000,5001,5002 TARGET
``` 

## Analyze the service
Netcat is convenient for sending one UDP datagram. UDP has no connection-close signal, and some Netcat versions ignore `-w` after receiving data, so keep standard input open briefly and use `timeout` to exit:

```bash
{printf 'help\n'; sleep 1; } | timeout 3 nc -u TARGET PORT
```

repeat for each service and follow the istruction
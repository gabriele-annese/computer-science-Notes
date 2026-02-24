
**Generate a key**
```bash
gpg --full-generate-key
```

**List all keys**
```bash
gpg --list-keys
```

**Export a public key**
```bash
gpg --armor --export uid > file.txt
```

**Export a private key**
```bash
gpg --armor --export-secret-keys uid > private.asc
```

**Crypt**
```bash
gpg --encrypt --armor --recipient uid .\test.txt
```

**Decrypt**
```bash
gpg --decrypt .\test.txt.asc > decrypt.txt
```

**Delete a Key**
```bash
gpg --delete-keys uid
```

**Delete a private key**
```bash
gpg --delete-secret-key CC50AC92FE10E9538B0A681ED8C8867DE40C23A1
```


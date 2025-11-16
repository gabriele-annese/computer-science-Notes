
# HEX conversion

La conversione degli hex funziona a base 16 e a seconda della posizione in cui si trova il numero va elevato 16 per la posizione e moltiplicato il numero per il risultato della potenza.

```
A = 10  
B = 11  
C = 12  
D = 13  
E = 14  
F = 15
```

Examples
```
0x1337

7 -> posizione 0 -> 16^0 = x1
3 -> posizione 1 -> 16^1 = x16
3 -> posizione 2 -> 16^2 = x256
1 -> posizione 1 -> 16^3 = x4096


7 x 1 = 7
3 x 16 = 48
3 x 256 = 768
1 x 4096 = 4096

7 + 48 + 768 + 4096 = 
```


# Binary Conversion

Each hex figure correspond to exactly 4 bit digit.

```
0 = 0000
1 = 0001
2 = 0010
3 = 0011
4 = 0100
5 = 0101
6 = 0110
7 = 0111
8 = 1000
9 = 1001
A = 1010
B = 1011
C = 1100
D = 1101
E = 1110
F = 1111

```


Examples conversion from **0x1337** to binary
```
1 = 0001
3 = 0011
3 = 0011
7 = 0111

0001 0011 0011 0111
```
# Tema 1 ROUTER

## Introducere

Am început tema prin a înțelege cum funcționează debugging-ul în Mininet împreună cu GDB și Wireshark. După mai multe încercări, am reușit în cele din urmă să instalez o extensie pentru GDB pe Mininet, **pwndbg**. A fost necesar să copiez extensia din folderul `home` al mașinii gazdă în folderul `home` al Mininet-ului, dar în cele din urmă a funcționat. Această extensie s-a dovedit a fi foarte utilă în rezolvarea temei.

---

## Implementare

Pe partea de implementare, am înțeles cum funcționează trimiterea unui pachet și utilitatea fiecărui header:

- **Ethernet header**
- **IP header**
- **ARP**
- **ICMP**

---

## Probleme întâmpinate și soluții

### 1. Endianness (Big Endian / Little Endian)

M-am lovit de multe probleme din cauza conversiilor între **big endian** și **little endian**. Adresele erau scrise în ordine inversă, iar uneori uitam să le convertesc. Cu ajutorul debugger-ului am reușit să identific erorile de acest tip. 

Am aflat, de exemplu, că:
- `ntohl()` convertește 32 de biți
- `ntohs()` convertește 16 biți

### 2. Checksum

Am întâmpinat probleme legate de calculul **checksum-ului**, cauzate tot de conversii greșite între endianness. GDB-ul m-a ajutat să identific și să corectez aceste erori.

### 3. ARP

La partea de ARP, uitam să setez câmpul `hwtype` cu valoarea **1**, ceea ce făcea ca host-urile să nu îmi trimită răspunsul ARP (`ARP reply`). 

Pentru a depana această problemă:
- Am folosit **Wireshark**
- Am analizat primul pachet `ARP Request` trimis de un host funcțional
- Am observat că acel câmp este setat pe `1`

Astfel, mi-am dat seama că pachetul meu de `ARP Request` se oprea la hostul de destinație deoarece era incomplet.

### 4. ICMP

Am întâmpinat mai multe dificultăți legate de pachetele **ICMP**:

- Am greșit de multe ori câmpul `type` atunci când construiam răspunsurile ICMP, dar în cele din urmă am reușit să le trimit corect.
- Am avut o altă eroare când uitam să setez câmpul `protocol` din cadrul `IP header-ului` pe **1** (valoarea corespunzătoare pentru ICMP). Pachetul era astfel interpretat ca **IPv4 generic**, deoarece valoarea era `0` implicit (am folosit `calloc` la alocare).

---

## Concluzie

Această temă a fost o bună ocazie de a înțelege în detaliu:

- Cum se trimit pachetele în rețea
- Cum se structurează un header Ethernet, IP, ARP și ICMP
- Cum funcționează debugging-ul cu GDB și Wireshark într-un mediu Mininet

Extensia `pwndbg` a fost de un real ajutor, iar folosirea combinată a GDB-ului și Wireshark-ului m-a ajutat să înțeleg mult mai bine funcționarea rețelelor la nivel de pachet.

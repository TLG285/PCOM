# Tema 3 HTTP Client

## Introducere

* In implementarea temei am plecat de la laboratorul de client HTTP. 
* De acolo am inteles cum functioneaza trimiterea mesajelor de tip http, cum sunt formatate si ce ar trebui sa contina un mesaj de acest tip.
* Scopul a fost înțelegerea detaliilor transferului HTTP, prelucrarea fisierelor de tip json si implementarea unui client care lucreaza cu un server deja existent. 
---

## Implementare

Pe partea de implementare am realizat:

* Adăugarea **host-ului** în header-ul HTTP pentru a evita eroarea `400 Unreachable`.
* Funcția `compute_post_request`: construiește un buffer cu câmpurile JSON și îl trimite serverului.
* Validarea buffer-ului de test local printr-un buffer cu două câmpuri date ca parametru.
* Am folosit si debuging cu **Wireshark** folosind filtrul `(ip.addr == 63.32.125.183) && (tcp.port == 8081)` pentru a inspecta exact pachetele HTTP.
* Setarea câmpurilor de autentificare (`username` și `password`) în buffer.
* Închiderea și redeschiderea socket-ului după fiecare request pentru a garanta trimiterea corectă a mesajelor.
* Extinderea funcțiilor pentru a trimite și **JWT token-ul** în toate request-urile necesare.
* Definirea unei funcții separate pentru fiecare comandă (`add_collection`, `get_collection`, `get_collections`, etc.), care:

  1. Trimite request-ul.
  2. Primește răspunsul HTTP.
  3. Extrage payload-ul JSON.
  4. Procesează și afișează datele conform formatului cerut.

---

## Probleme întâmpinate și soluții

### 1. Host lipsă în header

Am omis host-ul în request-urile POST și GET, rezultând `400 Unreachable`. Am adăugat linia `Host: <adresa>:<port>` în request și problema a fost rezolvată.

### 2. Gestionarea conexiunii TCP

Inițial nu închideam socket-ul după fiecare request, ceea ce ducea la blocaje și mesaje netrimise. Am apelat `close(sockfd)` la finalul fiecărei comenzi și apoi `open_connection()` din nou.

### 3. Logout admin și cookie expirat

La logout nu resetam cookie-ul, așa că păstram un cookie expirat și primeam `403 Already logged-in` la login-ul ulterior. Am adăugat resetarea cookie-ului imediat după `logout`.

### 4. Format URL și parametrizare

Specificația temei a folosit `/:movieId`, iar eu inițial am păstrat punctele literal în URL (ex: `/movies.:id`). Am corectat formatul la `/movies/<id>` pentru GET/POST.

### 5. Scanf și newline leftover

După `scanf()` newline-ul rămânea în buffer, perturbând citirile ulterioare. Am rezolvat cu `getchar()` după fiecare `scanf`.

### 6. Extract JSON payload și multiple "title"

Am filtrat strict câmpurile `title` și `owner` în funcția `get_collection`, fără a afișa `title`-urile filmelor în aceeași secțiune, prevenind astfel eroarea checker-ului `Multiple 'title' fields`.

### 7. Debugging cu GDB

Am folosit GDB pentru a urmări variabilele JSON înainte de trimitere și pentru a verifica alocările dinamice, rezolvând problemele de memory leak și de alocare inutilă (`body_data` cu `malloc(BUFLEN)`).

---

## Concluzie

Tema a fost repetitivă, dar excelentă pentru:

* Înțelegerea mecanismului HTTP prin socket-uri.
* Practica trimitere/recepție de header-e și payload JSON.
* Folosirea și debugging-ul cu Wireshark și GDB.

Pe viitor, ar fi utilă accesarea codului sursă al serverului pentru evitarea situatiilor in care serverul pica si nu putem implementa tema.
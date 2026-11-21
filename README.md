# DITTO

**D**eception, **I**ntrusion & **T**arpit **T**hreat **O**bservatory

*A self-hosted SSH/Telnet honeypot + tarpit with static malware analysis and a live dashboard. (UI and docs are in German.)*

Benannt nach dem Pokémon **Ditto**, das sich in exakte Kopien verwandelt — genau das macht ein Honeypot: Er gibt sich als echtes System aus, um Angreifer zu täuschen.

> ### ⚠️ Vibe-coded
> Dieses Projekt wurde **„vibe-coded“** mit Claude (Anthropic) zusammengebaut, in einem durchgehenden Dialog, ohne klassisches Software-Engineering und **ohne Sicherheitsaudit**. Es verarbeitet und speichert **echte Schadsoftware**. Betreibe es nur in einer isolierten Umgebung, auf eigene Verantwortung, und lies den Abschnitt [Sicherheit & Recht](#sicherheit--recht), bevor du irgendetwas ans Internet hängst.

---

## Was DITTO macht

DITTO bündelt drei Dinge und zeigt das Ergebnis auf einer Weboberfläche:

- **Honeypot (Cowrie)** — ein nachgebauter Linux-Server auf SSH (Port 22) und Telnet (Port 23). Angreifer „loggen sich ein“ und landen in einer simulierten Shell. Nichts davon ist echt, kein Befehl wird ausgeführt. Cowrie protokolliert Logins, Passwörter, Befehle und lädt die Dateien herunter, die Angreifer nachladen wollen.
- **Tarpit (endlessh)** — auf Port 2222 lauscht eine „Teergrube“. Sie schickt verbindenden Scannern endlos langsam ein SSH-Banner und hält sie so Minuten bis Tage fest, ohne selbst nennenswert Ressourcen zu brauchen.
- **Statische Malware-Analyse** — jede nachgeladene Datei wird zerlegt (Hashes, ELF-Struktur, Sektionen, Importe, Zeichenketten, IOCs), zu einer Schadsoftware-Familie eingeschätzt und beschrieben. **Dateien werden nie ausgeführt**, nur gelesen.

### Funktionen im Überblick

- Live-Dashboard mit Kennzahlen für 24 h und 7 Tage (Verbindungen, Login-Versuche, Befehle, Angreifer-IPs, Tarpit-Zeit).
- Automatische Einordnung der Honeypot-Sitzungen in Angriffsarten (IoT-Botnetz, Mining, Persistenz, Scan, …).
- Verlaufsdiagramme über 48 Stunden.
- Top-Listen: Benutzer/Passwort-Kombinationen, Befehle, Angreifer-IPs, **Herkunftsländer** (mit optionaler GeoIP-Datenbank).
- **Datei-Reports** pro Sample: Familie, Wirkung und Einsatzzweck in Klartext, ELF-Kopf, Segmente/Sektionen mit Entropie, importierte Funktionen, Packer-Erkennung, ssdeep, Toolchain/libc, und extrahierte IOCs (URLs, IPs, Domains, Mining-Pools, Befehle, Zugangsdaten). Loader-Skripte werden mit vollem Inhalt gezeigt.
- Breite Suche über Dateien, Familien, IPs, Länder, Server, Domains, Befehle und Fähigkeiten.
- Links zu VirusTotal und MalwareBazaar pro Hash.

## Aufbau

```
Angreifer ──▶ Cowrie (22/23)   ─┐
Scanner  ──▶ endlessh (2222)   ─┤  Logs + heruntergeladene Dateien
                                │
                        collector (Python)  ──▶  web/data/stats.json
                        statische Analyse   ──▶  web/data/report.json
                                │
                         Dashboard (web/)  ──▶  Browser
```

Der **Collector** liest nur die Logs und die heruntergeladenen Dateien und schreibt zwei JSON-Dateien. Das **Dashboard** sind statische HTML-Dateien, die diese JSONs laden. Keine Datenbank, kein Backend-Framework.

---

## Schnellstart (Docker)

Voraussetzung: Docker + Docker Compose. **Wichtig:** Port 22 ist hier der Honeypot — wenn dieser Host selbst SSH auf 22 nutzt, ändere zuerst die Ports (siehe unten).

```bash
git clone https://github.com/M0nkeynaut/ditto.git
cd ditto
cp .env.example .env            # Ports/Optionen anpassen
sh scripts/fetch-geoip.sh       # optional: Länder-Datenbank laden
docker compose up -d --build
```

Dashboard: **http://<host>:8080/**

## Installation

### Docker (empfohlen zum Ausprobieren)

Siehe Schnellstart. Die `docker-compose.yml` startet vier Container: `cowrie`, `endlessh`, `collector`, `web` (nginx). Daten liegen in Docker-Volumes (`cowrie-var`, `endlessh-logs`, `ditto-data`). Ports und Optionen stellst du in `.env` ein.

### LXC (z. B. auf Proxmox)

Einen **unprivilegierten Debian- oder Ubuntu-Container** anlegen. Zwei Wege:

- **Docker im LXC:** Im Container Docker installieren und dem Schnellstart folgen. Der LXC muss dafür „nesting“ erlauben (Proxmox: Options → Features → Nesting).
- **Nativ:** Dem Bare-Metal-Weg unten folgen.

### Bare-Metal (Debian/Ubuntu)

Der mitgelieferte Installer richtet **Tarpit, Collector und Dashboard** per systemd ein. Cowrie (den Honeypot) installierst du separat — am einfachsten als einzelnen Docker-Container oder nach der [offiziellen Cowrie-Anleitung](https://docs.cowrie.org/).

```bash
git clone https://github.com/M0nkeynaut/ditto.git
cd ditto
sudo sh scripts/install-baremetal.sh
# danach:
sudo nano /etc/ditto/ditto.env      # COWRIE_LOG_DIR / COWRIE_DL_DIR auf deine Cowrie-Pfade setzen
sh scripts/fetch-geoip.sh           # optional
sudo systemctl start ditto-collector.service
```

Der Collector läuft dann alle 2 Minuten (Timer), das Dashboard liegt auf Port 8080 (`ditto-web.service`).

Nur den Collector manuell laufen lassen (zum Testen):

```bash
COWRIE_LOG_DIR=/pfad/zu/cowrie/var/log/cowrie \
COWRIE_DL_DIR=/pfad/zu/cowrie/var/lib/cowrie/downloads \
ENDLESSH_UNIT=endlessh \
DITTO_DATA=./web/data \
python3 collector/ditto_collector.py all
```

## Konfiguration

Der Collector wird über Umgebungsvariablen gesteuert:

| Variable | Standard | Zweck |
|---|---|---|
| `COWRIE_LOG_DIR` | `/cowrie-var/log/cowrie` | Verzeichnis mit `cowrie.json*` |
| `COWRIE_DL_DIR` | `/cowrie-var/lib/cowrie/downloads` | Heruntergeladene Samples |
| `ENDLESSH_LOG` | `/endlessh/endlessh.log` | Logdatei von endlessh (`-v`) |
| `ENDLESSH_UNIT` | – | Alternativ: systemd-Unit, aus der per `journalctl` gelesen wird |
| `GEOIP_DB` | `/geoip/country.mmdb` | Optionale Länder-Datenbank (mmdb) |
| `DITTO_DATA` | `/web/data` | Zielordner für `stats.json`/`report.json` |
| `DITTO_INTERVAL` | `120` | Sekunden zwischen zwei Collector-Läufen (nur Docker-Loop) |
| `DITTO_LOOKBACK_DAYS` | `7` | Auswertungszeitraum |
| `DITTO_PORT` | `8080` | Port für den eingebauten Webserver (`serve`) |

Docker-Ports und der Fake-Hostname kommen aus `.env` (siehe `.env.example`).

### GeoIP (optional)

Für die Herkunftsländer lädt `scripts/fetch-geoip.sh` die freie Datenbank **IP to Country Lite** von [DB-IP](https://db-ip.com) (Lizenz CC BY 4.0) nach `geoip/country.mmdb`. Ohne diese Datei funktioniert alles weiter, Länder erscheinen dann als „unbekannt“.

---

## Sicherheit & Recht

Bitte ernst nehmen. Ein Honeypot zieht Angriffe an und speichert echte Schadsoftware.

- **Isolieren.** Betreibe DITTO in einem eigenen Netz/VLAN. Der Honeypot darf das restliche Netzwerk **nicht** erreichen können. Sperre ausgehende Verbindungen so weit wie möglich (Egress-Firewall); der Cowrie-Container braucht keinen Zugriff auf dein LAN.
- **Keine Samples ausführen.** Die heruntergeladenen Dateien sind echte Malware für verschiedene Architekturen. DITTO liest sie nur. Kopiere sie nicht auf andere Geräte und starte sie nicht.
- **Host-SSH.** Port 22 ist der Honeypot. Lege den echten Administrations-Zugang auf einen anderen Port und binde ihn nur ans Management-Netz. Verwechsle die beiden nicht.
- **Kein Zugangsschutz am Dashboard.** Das Dashboard hat keine Anmeldung. Stelle es nicht offen ins Internet, sondern hinter VPN, Reverse Proxy mit Auth oder nur im lokalen Netz bereit.
- **Tarpit im selben VLAN.** Liegt der Tarpit im selben VLAN wie andere Geräte, filtere den Verkehr direkt an seiner Netzwerkkarte (Host-Firewall), nicht nur am Router.
- **Recht.** Betreibe das nur auf Infrastruktur, die dir gehört oder für die du eine Erlaubnis hast. Das Vorhalten von Malware-Samples und das Protokollieren von Verbindungsdaten kann rechtliche und Datenschutz-Pflichten auslösen — kläre das für deine Region.
- **Updates.** Cowrie und die Basis-Images regelmässig aktualisieren.

---

## Wie die Analyse funktioniert (und ihre Grenzen)

- Die **Angriffsarten** und die **Familien-Einschätzung** beruhen auf Mustererkennung in Befehlen und Byte-Signaturen (typische Marker von Mirai, Gafgyt, Tsunami, XMRig, Dofloo …). Bei **gestrippten oder gepackten** Dateien bleibt die Familie oft „unbestimmt“, obwohl die Datei bösartig ist.
- Die **IOCs** werden per Heuristik aus Zeichenketten gezogen. Dabei entstehen gelegentlich **Fehltreffer** (z. B. interne libc- oder Go-Laufzeit-Strings). Betrachte sie als Hinweise, nicht als Beweise.
- Die **Länderzuordnung** macht eine GeoIP-Datenbank. Das Land der IP ist selten das Land des Täters: Angriffe laufen über gekaperte Geräte, gemietete Server oder VPNs.
- Die statische Analyse ersetzt keine dynamische Analyse in einer Sandbox.

## Mitwirkende Projekte

- [Cowrie](https://github.com/cowrie/cowrie) — SSH/Telnet-Honeypot (BSD)
- [endlessh](https://github.com/skeeto/endlessh) — SSH-Tarpit (Public Domain)
- [pyelftools](https://github.com/eliben/pyelftools), [ssdeep](https://ssdeep-project.github.io/) — Analyse
- [DB-IP](https://db-ip.com) — IP-zu-Land-Datenbank (CC BY 4.0)

## Lizenz

[MIT](LICENSE). Ohne jede Gewährleistung.

---

*Vibe-coded mit Claude. Wenn du damit Angreifer beim Scheitern beobachtest: viel Spass. Wenn etwas kaputt ist: war ja klar. 🫠*

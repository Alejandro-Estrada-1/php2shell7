<?php
// Simula una aplicacion real en CentOS 7 con /etc/php.ini por defecto (display_errors = Off):
// 1) Siempre renderiza la plantilla HTML completa (~81 KB), no un simple "OK".
// 2) Como display_errors = Off en CentOS 7 de fabrica, cuando Fase 2 envia ?page=zz_..._nofile
//    el include() falla en silencio (solo escribe en /var/log/httpd/error_log) y la respuesta
//    mide exactamente los mismos 81902 bytes que el baseline.
if (isset($_GET['page'])) {
    include($_GET['page']);
}
$head = "<!doctype html>\n<html>\n<head>\n<!-- Title -->\n<title>PAGINA PRUEBA </title>\n<!-- Required Meta Tags Always Come First -->\n";
$tail = "\n</body>\n</html>\n";
$pad_len = 81902 - strlen($head) - strlen($tail);
echo $head . str_repeat("A", $pad_len) . $tail;

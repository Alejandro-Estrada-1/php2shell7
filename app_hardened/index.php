<?php
// Version ENDURECIDA: allowlist de paginas. El input nunca llega a include().
$pages = [
    'home'    => __DIR__ . '/pages/home.php',
    'contact' => __DIR__ . '/pages/contact.php',
];

$key = $_GET['page'] ?? 'home';

if (!isset($pages[$key])) {
    http_response_code(404);
    header('Content-Type: text/plain');
    echo "404 - pagina no encontrada\n";
    exit;
}

include $pages[$key];

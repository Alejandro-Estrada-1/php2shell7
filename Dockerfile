FROM php:7.4.33-apache

# Copia la aplicación vulnerable
COPY app/ /var/www/html/

# Copia configuración de PHP (habilita session.upload_progress)
COPY php.ini /usr/local/etc/php/conf.d/zz-php2shell.ini

# Crea directorio de sesiones con permisos
RUN mkdir -p /tmp/sessions && chmod 777 /tmp/sessions

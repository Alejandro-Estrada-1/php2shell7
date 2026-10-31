# Laboratorio CentOS 7 + PHP 5.4.16 (el PHP de fábrica de CentOS 7)
# Reproduce el escenario "legacy" para comparar con el lab de PHP 7.4.
FROM centos:7

# CentOS 7 está EOL: los repos oficiales ya no funcionan. Apuntamos a vault.
RUN rm -f /etc/yum.repos.d/CentOS-*.repo && \
    cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOF'
[base]
name=CentOS-7 - Base - Vault
baseurl=https://vault.centos.org/7.9.2009/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

[updates]
name=CentOS-7 - Updates - Vault
baseurl=https://vault.centos.org/7.9.2009/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
EOF

# El php de fábrica de CentOS 7 es exactamente 5.4.16 (mod_php)
RUN yum install -y httpd php php-cli && yum clean all

# App vulnerable + ficheros señuelo, dentro de la imagen y con dueño apache
# (así el webroot es escribible como en un servidor real)
COPY app/ /var/www/html/
RUN chown -R apache:apache /var/www/html

COPY entry.sh /entry.sh
RUN chmod +x /entry.sh

EXPOSE 80
CMD ["/entry.sh"]

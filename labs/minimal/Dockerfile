FROM php:8.4.26-apache-trixie

# Single-worker prefork for deterministic heap layout
COPY apache.conf /etc/apache2/conf-enabled/zz-archonx.conf

# Stock production php.ini + lab overrides
RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini
COPY php.ini /usr/local/etc/php/conf.d/zz-archonx.ini

# Simple index page — the exploit needs a reachable endpoint, not app code
COPY index.php /var/www/html/index.php

# /out volume for file-based I/O mode
RUN mkdir -p /out && chown www-data:www-data /out

EXPOSE 80

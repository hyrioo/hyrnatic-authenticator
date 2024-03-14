FROM phpdockerio/php:8.3-fpm

# Install selected extensions and other stuff
RUN apt-get update \
    && apt-get -y --no-install-recommends install \
    supervisor \
    cron \
    git \
    ssh \
    nano \
    vim \
    openssl \
    php8.3-common \
    php8.3-mysql \
    php8.3-sqlite3 \
    php8.3-gd \
    php8.3-bcmath \
    php8.3-intl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/*

# Install Composer
RUN cd /usr/src && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Setup supervisor
RUN mkdir -p /var/log/supervisor
COPY .docker/php/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD /usr/bin/supervisord

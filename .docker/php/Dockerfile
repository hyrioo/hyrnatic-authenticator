FROM phpdockerio/php:8.1-fpm

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
    php8.1-common \
    php8.1-mysql \
    php8.1-gd \
    php8.1-bcmath \
    php8.1-intl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/*

# Install Composer
RUN cd /usr/src && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Setup supervisor
RUN mkdir -p /var/log/supervisor
COPY .docker/php/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD /usr/bin/supervisord

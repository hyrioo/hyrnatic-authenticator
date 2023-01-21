FROM phpdockerio/php:8.0-fpm

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
    php8.0-common \
    php8.0-mysql \
    php8.0-gd \
    php8.0-bcmath \
    php8.0-intl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/doc/*

# Install Composer
RUN cd /usr/src
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Setup supervisor
RUN mkdir -p /var/log/supervisor
COPY .docker/php/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY .docker/php/php.ini /etc/php/8.0/fpm/php.ini

CMD /usr/bin/supervisord

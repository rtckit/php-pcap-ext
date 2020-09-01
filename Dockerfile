FROM php:7.4-cli-alpine

RUN apk add $PHPIZE_DEPS && \
  cd /usr/src && \
  tar -xf php.tar.xz && \
  cd php-* && \
  apk add libpcap libpcap-dev

COPY . /usr/src/php-pcap-ext

WORKDIR /usr/src/php-pcap-ext

RUN phpize && \
  ./configure && \
  make && \
  (TEST_PHP_ARGS="-q --show-out" make test || exit 0) && \
  make install && \
  echo "extension=pcap.so" > /usr/local/etc/php/conf.d/pcap.ini

CMD ["php", "-i"]

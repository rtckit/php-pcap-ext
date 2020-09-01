# This file is intended solely to facilitate development specific processes
REPOSITORY=rtckit/php-pcap-ext-dev

image:
	docker build -t ${REPOSITORY} .

local-image:
	docker build -v `pwd`:/usr/src/php-pcap-ext:rw -t ${REPOSITORY} .

run: image
	docker run --rm -t ${REPOSITORY}

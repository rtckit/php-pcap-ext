# This file is intended solely to facilitate development specific processes
REPOSITORY=rtckit/php-pcap-ext-dev

image:
	docker build -t ${REPOSITORY} .

run: image
	docker run --rm -it ${REPOSITORY}

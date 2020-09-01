# PHP Packet Capture

Stream driven PHP packet capture extension.

[![Build Status](https://travis-ci.org/rtckit/php-pcap-ext.svg?branch=master)](https://travis-ci.org/rtckit/php-pcap-ext) ![Version](https://img.shields.io/badge/version-v0.6.0-green) ![License](https://img.shields.io/badge/license-MIT-blue)

## Usage

The `pcap` extension has been developed against PHP 7.4+ and regularly tested against the upcoming PHP 8.

The extension provides bindings for [libpcap](https://github.com/the-tcpdump-group/libpcap) and exposes its functionality via PHP streams; the packet formatting is consistent with the `pcap` file format (learn more [here](https://wiki.wireshark.org/Development/LibpcapFileFormat) and [here](https://formats.kaitai.io/pcap/index.html)).

It's also worth familiarizing yourself with [libpcap and tcpdump](https://www.tcpdump.org/index.html).

## Build

In order to build the extension from source, make sure the environment supports the typical C/C++ build essentials for your platform (`build-essential`), the PHP development files (`php-dev`) as well as the libpcap library and its respective development files (`libpcap-dev`).

```sh
phpize
./configure
make
```

## Tests

Before running the test suite, make sure the user has the ability to capture network packets (root or CAP_RAW).

```sh
make test
```

## License

MIT, see [LICENSE file](LICENSE).

### Acknowledgments

* [libpcap](https://github.com/the-tcpdump-group/libpcap)

### Contributing

Bug reports (and small patches) can be submitted via the [issue tracker](https://github.com/rtckit/php-pcap-ext/issues). Forking the repository and submitting a Pull Request is preferred for substantial patches.

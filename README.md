# PHP Packet Capture

Stream driven PHP packet capture extension.

[![Build Status](https://travis-ci.com/rtckit/php-pcap-ext.svg?branch=master)](https://travis-ci.com/rtckit/php-pcap-ext) ![Version](https://img.shields.io/badge/version-v0.6.5-green) ![License](https://img.shields.io/badge/license-MIT-blue)

## Usage

The `pcap` extension has been developed against PHP 7.1+ and regularly tested against the nightly PHP 8 build; from an operating system perspective, the ubiquity of Linux makes it the only target. The supported architectures are x86_64 and arm64.

The extension provides bindings for [libpcap](https://github.com/the-tcpdump-group/libpcap) and exposes its functionality via PHP streams; the packet formatting is consistent with the `pcap` file format (learn more [here](https://wiki.wireshark.org/Development/LibpcapFileFormat) and [here](https://formats.kaitai.io/pcap/index.html)). The functionality is deliberately limited to I/O operations, the actual packet parsing/crafting should be performed using pure PHP (some relevant supporting libraries to be published soon).

It's also worth familiarizing yourself with [libpcap and tcpdump](https://www.tcpdump.org/index.html).

A typical capture session can be initiated as follows:

```php
$fp = fopen('pcap://eth0', 'r');
```

The above will initiate the capture session on the `eth0` interface; one can retrieve all network interfaces via `net_get_interfaces()`. An `any` meta-interface is also available.

There are several configuration options exposed through stream contexts:

```php
$context = stream_context_create([
  'pcap' => [
    'snaplen'   => 2048,  // Snapshot length (truncates packets)
    'promisc'   => true,  // Enables promiscuous mode
    'immediate' => true,  // Sets immediate mode (skips buffering)
    'blocking'  => false, // Enables/disables blocking mode (useful in stream_select loops)
    'timeout'   => 0.100, // I/O timeout, in seconds
    'filter'    => 'dst port 53', // Reference: https://www.tcpdump.org/manpages/pcap-filter.7.html
  ],
]);

$fp = fopen('pcap://any', 'r', false, $context);
```

All I/O operations are no different than any other PHP stream, for example:

```php
$fp = fopen('pcap://eth0', 'r');

$header = unpack('LtsSec/LtsUsec/LcapLen/Llen', fread($fp, 16)); // pcap packet header, using local machine endianness
$frame = fread($fp, $header['capLen']);

var_dump($header)
/*
array(4) {
  ["tsSec"]=>
  int(1598997114)
  ["tsUsec"]=>
  int(239648)
  ["capLen"]=>
  int(96)
  ["len"]=>
  int(96)
}
*/

// process($frame) ...

// Inject raw packets (including the link layer data) by writing to the stream
$count = fwrite($fp, $packet);
```

The [tests](https://github.com/rtckit/php-pcap-ext/tree/master/tests) directory show cases some usage examples.

## Build

In order to build the extension from source, make sure the environment supports the typical C/C++ build essentials for your platform (`build-essential`), the PHP development files (`php-dev`) as well as the libpcap library and its respective development files (`libpcap-dev`).

```sh
phpize
./configure
make
```

## Tests

Before running the test suite, make sure the user has the ability to capture network packets (root or `CAP_NET_RAW`).

```sh
make test
```

## FFI Alternative

A fully compilable [FFI packet capture](https://github.com/rtckit/php-pcap-ffi) package is also available; the underlying environment would still have the provide the libpcap library as well as the FFI dependencies (libffi and the PHP FFI extension). Otherwise, the FFI package can be used as a drop-in replacement when it makes sense to do so.

## License

MIT, see [LICENSE file](LICENSE).

### Acknowledgments

* [libpcap](https://github.com/the-tcpdump-group/libpcap) by The Tcpdump Group, BSD licensed.

### Contributing

Bug reports (and small patches) can be submitted via the [issue tracker](https://github.com/rtckit/php-pcap-ext/issues). Forking the repository and submitting a Pull Request is preferred for substantial patches.

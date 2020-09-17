### To Do
 * Failed operations to throw Exceptions over issuing PHP warnings (via a toggle)
 * Improved documentation
 * IPv6 oriented tests
 * Expose useful data pointers via `stream_metadata` (accessible through `stream_get_meta_data`)

### 0.6.4
 * Support for older PHP versions (7.1+)

### 0.6.2
 * Improved UDP/DNS tests
 * Selectable file descriptor (for `stream_cast`) is now cached
 * Validates `php_url_parse` succeeds and returns a `host` property (the network device name)
 * Packet injection tests, via ARP
 * Strict type enforcement within tests

### 0.6.0
 * First public release

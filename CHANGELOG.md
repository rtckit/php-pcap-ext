### To Do
 * Failed operations to throw Exceptions over issuing PHP warnings (via a toggle)
 * Expose useful data pointers via `stream_metadata` (accessible through `stream_get_meta_data`)
 * Add tests covering stream closing
 * Add tests covering packet injection

### Upcoming Release
 * Improved UDP/DNS tests
 * Selectable file descriptor (for `stream_cast`) is now cached
 * Validates `php_url_parse` succeeds and returns a `host` property (the network device name)

### 0.6.0
 * First public release

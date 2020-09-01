--TEST--
fopen against bogus URLs
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

$dev = current(array_keys(net_get_interfaces()));
if (!$dev) {
  die('Cannot find any viable network devices');
}

$fp = fopen('pcap.bogus://' . $dev, 'r');
var_dump($fp);

$fp = fopen('pcap://' . $dev . '/path', 'r');
var_dump($fp);

$fp = fopen('pcap://' . $dev . '?query=string', 'r');
var_dump($fp);

print "done!";
?>
--EXPECTF--
Warning: fopen(): Unable to find the wrapper "pcap.bogus" - did you forget to enable it when you configured PHP? in %s on line %d

Warning: fopen(pcap.bogus://%s): %s to open stream: No such file or directory in %s on line %d
bool(false)

Warning: fopen(): Unsupported path: /path in %s on line %d

Warning: fopen(pcap://%s/path): %s to open stream: operation failed in %s on line %d
bool(false)

Warning: fopen(): Unsupported query: query=string in %s on line %d

Warning: fopen(pcap://%s?query=string): %s to open stream: operation failed in %s on line %d
bool(false)
done!

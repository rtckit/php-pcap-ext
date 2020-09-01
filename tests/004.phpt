--TEST--
fopen against bogus devices
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

$fp = fopen('pcap://' . uniqid('bogus'), 'r');
var_dump($fp);

print "done!";
?>
--EXPECTF--
Warning: fopen(): Unknown device: bogus%s in %s on line %d

Warning: fopen(pcap://bogus%s): %s to open stream: operation failed in %s on line %d
bool(false)
done!

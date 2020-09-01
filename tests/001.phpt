--TEST--
extension_loaded pcap
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

var_dump(extension_loaded('pcap'));

print "done!";
?>
--EXPECTF--
bool(true)
done!

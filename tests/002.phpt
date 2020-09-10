--TEST--
stream_get_wrappers pcap
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

declare(strict_types = 1);

var_dump(in_array('pcap', stream_get_wrappers()));

print "done!";
?>
--EXPECT--
bool(true)
done!

--TEST--
fopen devices from net_get_interfaces
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

$devs = 0;

foreach (array_keys(net_get_interfaces()) as $dev) {
  $fp = fopen('pcap://' . $dev, 'r');

  if (!$fp) {
    die('Could not open device ' . $dev);
  }

  $devs++;

  fclose($fp);
}

print "successfully initiated capture on {$devs} devices\n";
print "done!";
?>
--EXPECTF--
successfully initiated capture on %d devices
done!

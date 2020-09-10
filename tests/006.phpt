--TEST--
fopen without privileges
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

declare(strict_types = 1);

$dev = current(array_keys(net_get_interfaces()));
if (!$dev) {
  die('Cannot find any viable network devices');
}

$user = posix_getpwnam('daemon');
if (empty($user) || empty($user['uid'])) {
  die('Cannot find a suitable non-root user');
}

posix_setuid($user['uid']);
posix_seteuid($user['uid']);
posix_setgid($user['gid']);
posix_setegid($user['gid']);

$fp = fopen('pcap://' . $dev, 'r');
var_dump($fp);
?>
--EXPECTF--
Warning: fopen(): Cannot open raw sockets (check privileges or CAP_NET_RAW capability) in %s on line %d

Warning: fopen(pcap://%s): %s to open stream: operation failed in %s on line %d
bool(false)

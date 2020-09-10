--TEST--
fwrite/fread ARP to IPv4 gateway
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

declare(strict_types = 1);

require('helpers.php');

$dev = $gw = null;

foreach (getRoutingTable() as $record) {
  if (!empty($record['Iface']) && !empty($record['Gateway']) && ($record['Gateway'] !== '00000000')) {
    $dev = $record['Iface'];
    $hex = $record['Gateway'];
    $gw = [];

    while (strlen($hex)) {
      $byte = hexdec(substr($hex, -2));
      $hex = substr($hex, 0, -2);
      $gw[] = $byte;
    }

    $gw = implode('.', $gw);
    break;
  }
}

if (is_null($dev)) {
  die('Cannot find a suitable network device');
}

$mac = trim(file_get_contents('/sys/class/net/' . $dev . '/address'));
$ip = null;

foreach (net_get_interfaces()[$dev]['unicast'] as $config) {
  if ($config['family'] == 2) {
    $ip = $config['address'];
    break;
  }
}

var_dump($dev);
var_dump($mac);
var_dump($ip);
var_dump($gw);

$packet = craftEthernet2Frame([
  'destination' => 'ff:ff:ff:ff:ff:ff',
  'source' => $mac,
  'etherType' => 0x0806,
  'data' => craftArpFrame([
    'htype' => 1,
    'ptype' => 0x0800,
    'hsize' => 6,
    'psize' => 4,
    'opcode' => 1,
    'senderEtherAddress' => $mac,
    'senderProtoAddress' => $ip,
    'targetEtherAddress' => '00:00:00:00:00:00',
    'targetProtoAddress' => $gw,
  ]),
]);

var_dump(strlen($packet));

$context = stream_context_create([
  'pcap' => [
    'snaplen'   => 2048,
    'immediate' => true,
    'timeout'   => 0.100,
    'filter'    => 'arp',
  ],
]);

$fp = fopen('pcap://' . $dev, 'rw', false, $context);

if (!$fp) {
  die('Cannot initiate packet capture');
}

var_dump($fp);

// Trigger capture activation, expect nothing to read
var_dump(fread($fp, 16));

$bytes = fwrite($fp, $packet);
var_dump($bytes);

$captures = [$fp];
$read = [];
$write = $except = null;

$gwMac = null;

while (!$gwMac) {
  $read = $captures;

  if (stream_select($read, $write, $except, 0, 100000)) {
    foreach ($read as $r) {
      while ($_header = fread($r, 16)) {
        $header = unpack('LtsSec/LtsUsec/LcapLen/Llen', $_header);
        $frame = parseEthernet2Frame(fread($r, $header['capLen']));

        if ($frame['etherType'] == 0x0806) { // ARP
          $arp = parseArpFrame($frame['data']);

          if (($arp['opcode'] == 2) && ($arp['senderProtoAddress'] == $gw) && ($arp['targetProtoAddress'] == $ip) && ($arp['targetEtherAddress'] == $mac)) {
            $gwMac = $arp['senderEtherAddress'];
            break;
          }
        }
      }
    }
  }
}

var_dump($gwMac);

print "done!";
?>
--EXPECTF--
string(%d) "%s"
string(17) "%x:%x:%x:%x:%x:%x"
string(%d) "%d.%d.%d.%d"
string(%d) "%d.%d.%d.%d"
int(42)
resource(%d) of type (stream)
string(0) ""
int(42)
string(17) "%x:%x:%x:%x:%x:%x"
done!

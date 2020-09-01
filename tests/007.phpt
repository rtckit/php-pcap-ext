--TEST--
fread ICMP ping traffic
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

require('helpers.php');

$ip = gethostbyname('example.com');
var_dump($ip);

$count = 4;

$context = stream_context_create([
  'pcap' => [
    'snaplen'   => 2048,
    'immediate' => true,
    'timeout'   => 0.100,
    'filter'    => 'host ' . $ip,
  ],
]);

$fp = fopen('pcap://any', 'r', false, $context);
var_dump($fp);

// Trigger capture activation, expect nothing to read
var_dump(fread($fp, 16));

// Fire the ping requests we want to sniff
shell_exec("ping -c {$count} ${ip} 2>/dev/null >/dev/null &");

$captures = [$fp];
$read = [];
$write = $except = null;

$localMac = '';
$remoteMac = '';
$requests = 0;
$replies = 0;

$startedAt = time();

while (($requests < $count) || ($replies < $count)) {
  $read = $captures;

  if (stream_select($read, $write, $except, 0, 100000)) {
    foreach ($read as $r) {
      while ($_header = fread($r, 16)) {
        $header = unpack('LtsSec/LtsUsec/LcapLen/Llen', $_header);
        $frame = parseLinuxSLLFrame(fread($r, $header['capLen']));

        if ($frame['packetType'] === 0) {
          $remoteMac = $frame['address'];
        }

        if ($frame['packetType'] === 4) {
          $localMac = $frame['address'];
        }

        if ($frame['etherType'] === 8) { // IPv4
          $ipv4 = parseIPv4Frame($frame['data']);

          if ($ipv4['protocol'] === 1) { // ICMP
            $icmp = parseICMPFrame($ipv4['data']);

            if($icmp['type'] === 8) {
              echo "Ping {$ipv4['srcAddr']} -> {$ipv4['dstAddr']}\n";
              $requests++;
            }

            if($icmp['type'] === 0) {
              echo "Pong {$ipv4['srcAddr']} -> {$ipv4['dstAddr']}\n";
              $replies++;
            }
          }
        }
      }
    }
  }
}

var_dump($localMac);
var_dump($remoteMac);

print "done!";
?>
--EXPECTF--
string(%d) "%d.%d.%d.%d"
resource(%d) of type (stream)
string(0) ""
Ping %d.%d.%d.%d -> %d.%d.%d.%d
Pong %d.%d.%d.%d -> %d.%d.%d.%d
Ping %d.%d.%d.%d -> %d.%d.%d.%d
Pong %d.%d.%d.%d -> %d.%d.%d.%d
Ping %d.%d.%d.%d -> %d.%d.%d.%d
Pong %d.%d.%d.%d -> %d.%d.%d.%d
Ping %d.%d.%d.%d -> %d.%d.%d.%d
Pong %d.%d.%d.%d -> %d.%d.%d.%d
string(17) "%x:%x:%x:%x:%x:%x"
string(17) "%x:%x:%x:%x:%x:%x"
done!

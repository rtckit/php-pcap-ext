--TEST--
fread UDP DNS traffic
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

require('helpers.php');

// Use OpenDNS public nameservers
$ns = '208.67.222.222';
$fqdn = 'example.com';

$context = stream_context_create([
  'pcap' => [
    'snaplen'   => 2048,
    'immediate' => true,
    'timeout'   => 0.100,
    'filter'    => 'host ' . $ns,
  ],
]);

$fp = fopen('pcap://any', 'r', false, $context);
var_dump($fp);

// Trigger capture activation, expect nothing to read
var_dump(fread($fp, 16));

// Fire the DNS queries we want to sniff
shell_exec("sleep 0 && dig @{$ns} {$fqdn} A 2>/dev/null >/dev/null &");
shell_exec("sleep 1 && dig @{$ns} {$fqdn} AAAA 2>/dev/null >/dev/null &");

$captures = [$fp];
$read = [];
$write = $except = null;

$localMac = '';
$remoteMac = '';
$ipv4Request = false;
$ipv4Response = false;
$ipv4Addr = '';
$ipv6Request = false;
$ipv6Response = false;
$ipv6Addr = '';
$replies = 0;

$startedAt = time();

while (!$ipv4Request || !$ipv4Response || !$ipv6Request || !$ipv6Response) {
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

          if ($ipv4['protocol'] === 17) { // UDP
            $udp = parseUDPFrame($ipv4['data']);

            if(($udp['srcPort'] == 53) || ($udp['dstPort'] == 53)) { // DNS
              $dns = parseDNSMesage($udp['data']);

              if ($dns['qr'] === false) { // Query
                if ($dns['queries'][0]['type'] === 1) { // A
                  $ipv4Request = true;
                  echo "A DNS query for {$dns['queries'][0]['name']}\n";
                } elseif ($dns['queries'][0]['type'] === 28) { // AAAA
                  $ipv6Request = true;
                  echo "AAAA DNS query for {$dns['queries'][0]['name']}\n";
                }
              } else { // Answer
                if ($dns['answers'][0]['type'] === 1) { // A
                  $ipv4Response = true;
                  $ipv4Addr = $dns['answers'][0]['address'];
                  echo "A DNS reply for {$dns['queries'][0]['name']}: {$dns['answers'][0]['address']} TTL={$dns['answers'][0]['ttl']}\n";
                } elseif ($dns['answers'][0]['type'] === 28) { // AAAA
                  $ipv6Response = true;
                  $ipv6Addr = $dns['answers'][0]['address'];
                  echo "AAAA DNS reply for {$dns['queries'][0]['name']}: {$dns['answers'][0]['address']} TTL={$dns['answers'][0]['ttl']}\n";
                }
              }
            }
          }
        }
      }
    }
  }
}

var_dump($ipv4Addr === filter_var($ipv4Addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
var_dump($ipv6Addr === filter_var($ipv6Addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6));

var_dump($localMac);
var_dump($remoteMac);

print "done!";
?>
--EXPECTF--
resource(%d) of type (stream)
string(0) ""
A DNS query for example.com.
A DNS reply for example.com.: %d.%d.%d.%d TTL=%d
AAAA DNS query for example.com.
AAAA DNS reply for example.com.: %x:%x:%x:%x:%x:%x:%x:%x TTL=%d
bool(true)
bool(true)
string(17) "%x:%x:%x:%x:%x:%x"
string(17) "%x:%x:%x:%x:%x:%x"
done!

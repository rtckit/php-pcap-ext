--TEST--
fread TCP HTTP traffic
--SKIPIF--
<?php if (!extension_loaded('pcap')) { echo 'skip'; } ?>
--FILE--
<?php

declare(strict_types = 1);

require('helpers.php');

$ip = gethostbyname('example.com');
var_dump($ip);

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

// Fire the HTTP request we want to sniff
shell_exec("curl http://{$ip}/ -H 'Host: example.com' -H 'User-Agent: PHP Pcap Extension Tester' -H 'Accept: text/html' 2>/dev/null >/dev/null &");

$captures = [$fp];
$read = [];
$write = $except = null;

$localMac = '';
$remoteMac = '';
$foundRequest = false;
$foundResponse = false;

$startedAt = time();

while (!$foundRequest || !$foundResponse) {
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

          if ($ipv4['protocol'] === 6) { // TCP
            $tcp = parseTCPSegment($ipv4['data']);

            // Test for our HTTP request
            if (!$foundRequest && ($ipv4['dstAddr'] === $ip) && ($tcp['dstPort'] === 80) && strlen($tcp['data'])) {
              $lines = explode("\r\n", $tcp['data']);

              if (isset($lines[0]) && ($lines[0] === 'GET / HTTP/1.1')) {
                $foundRequest = true;

                foreach ($lines as $line) {
                  if (strpos($line, 'Host:') === 0) {
                    var_dump($line);
                    continue;
                  }

                  if (strpos($line, 'User-Agent:') === 0) {
                    var_dump($line);
                    continue;
                  }

                  if (strpos($line, 'Accept:') === 0) {
                    var_dump($line);
                    continue;
                  }
                }
              }
            }

            // Test for remote HTTP response segment
            if (!$foundResponse && ($ipv4['srcAddr'] === $ip) && ($tcp['srcPort'] === 80) && strlen($tcp['data'])) {
              $lines = explode("\r\n", $tcp['data']);

              if (isset($lines[0]) && ($lines[0] === 'HTTP/1.1 200 OK')) {
                $foundResponse = true;

                foreach ($lines as $line) {
                  if (strpos($line, 'Content-Type:') === 0) {
                    var_dump($line);
                    continue;
                  }

                  if (strpos($line, 'Date:') === 0) {
                    var_dump($line);
                    continue;
                  }

                  if (strpos($line, 'Content-Length:') === 0) {
                    var_dump($line);
                    continue;
                  }
                }
              }
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
string(17) "Host: example.com"
string(37) "User-Agent: PHP Pcap Extension Tester"
string(17) "Accept: text/html"
string(38) "Content-Type: text/html; charset=UTF-8"
string(35) "Date: %s"
string(20) "Content-Length: %d"
string(17) "%x:%x:%x:%x:%x:%x"
string(17) "%x:%x:%x:%x:%x:%x"
done!

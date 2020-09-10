<?php

declare(strict_types = 1);

function parseLinuxSLLFrame(string $body): array {
  $ret = unpack('npacketType/narphrd/naddressLength', $body);
  $ret['address'] = formatEtherAddr(substr($body, 6, $ret['addressLength']));
  $ret['etherType'] = unpack('v', $body, 14)[1];
  $ret['data'] = substr($body, 16);

  return $ret;
}

function parseEthernet2Frame(string $body): array {
  $ret = [];
  $ret['destination'] = formatEtherAddr(substr($body, 0, 6));
  $ret['source'] = formatEtherAddr(substr($body, 6, 6));
  $ret['etherType'] = unpack('n', $body, 12)[1];
  $ret['data'] = substr($body, 14);

  return $ret;
}

function craftEthernet2Frame(array $frame): string {
  $ret = encodeEtherAddr($frame['destination']);
  $ret .= encodeEtherAddr($frame['source']);
  $ret .= pack('n', $frame['etherType']);
  $ret .= $frame['data'];

  return $ret;
}

function parseArpFrame(string $body): array {
  $ret = unpack('nhtype/nptype/chsize/cpsize/nopcode', $body);
  $ret['senderEtherAddress'] = formatEtherAddr(substr($body, 8, $ret['hsize']));
  $ret['targetEtherAddress'] = formatEtherAddr(substr($body, 18, $ret['hsize']));

  if ($ret['ptype'] == 0x0800) {
    $ret['senderProtoAddress'] = long2ip(unpack('N', $body, 14)[1]);
    $ret['targetProtoAddress'] = long2ip(unpack('N', $body, 24)[1]);
  }

  return $ret;
}

function craftArpFrame(array $frame): string {
  $ret = pack('nnccn', $frame['htype'], $frame['ptype'], $frame['hsize'], $frame['psize'], $frame['opcode']);
  $ret .= encodeEtherAddr($frame['senderEtherAddress']);
  $ret .= pack('N', ip2long($frame['senderProtoAddress']));
  $ret .= encodeEtherAddr($frame['targetEtherAddress']);
  $ret .= pack('N', ip2long($frame['targetProtoAddress']));

  return $ret;
}

function parseIPv4Frame(string $body): array {
  $ret = unpack('Cbyte0/Ctos/ntotalLength/nidentification/nword3/Cttl/Cprotocol/nchecksum/NsrcAddr/NdstAddr', $body);

  $ret['srcAddr'] = long2ip($ret['srcAddr']);
  $ret['dstAddr'] = long2ip($ret['dstAddr']);

  $ret['version'] = $ret['byte0'] >> 4;
  $ret['ihl'] = ($ret['byte0'] - ($ret['version'] << 4)) * 4;
  unset($ret['byte0']);

  $ret['flags'] = $ret['word3'] >> 13;
  $ret['offset'] = $ret['word3'] & 0x1FFF;
  unset($ret['word3']);

  $ret['options'] = substr($body, 20, $ret['ihl'] - 20);
  $ret['data'] = substr($body, $ret['ihl']);

  return $ret;
}

function parseICMPFrame(string $body): array {
  $ret = unpack('ctype/ccode/nchecksum', $body);
  $ret['data'] = substr($body, 4, 4);

  return $ret;
}

function parseUDPFrame(string $body): array {
  $ret = unpack('nsrcPort/ndstPort/nlength/nchecksum', $body);
  $ret['data'] = substr($body, 8, $ret['length'] - 8);

  return $ret;
}

function parseDNSMesage(string $body): array {
  $ret = unpack('ntransaction/nflags/nquestions/nanswerRRs/nauthorityRRs/nadditionalRRs', $body);

  $ret['qr'] = ($ret['flags'] >> 15) ? true : false;
  $ret['opcode'] = ($ret['flags'] >> 11) & 0b1111;
  $ret['aa'] = (($ret['flags'] >> 10) & 0b1) ? true : false;
  $ret['tc'] = (($ret['flags'] >> 9) & 0b1) ? true : false;
  $ret['rd'] = (($ret['flags'] >> 8) & 0b1) ? true : false;
  $ret['ra'] = (($ret['flags'] >> 7) & 0b1) ? true : false;
  $ret['rcode'] = $ret['flags'] & 0b1111;

  $offset = 12;

  $ret['queries'] = [];
  for ($i = 0; $i < $ret['questions']; $i++) {
    $ret['queries'][$i] = [
      'name' => '',
      'type' => 0,
      'class' => 0,
    ];

    while($len = unpack('c', $body, $offset)[1]) {
      $offset++;
      $ret['queries'][$i]['name'] .= substr($body, $offset, $len) . '.';

      $offset += $len;
    }

    $params = unpack('ntype/nclass', $body, ++$offset);
    $ret['queries'][$i]['type'] = $params['type'];
    $ret['queries'][$i]['class'] = $params['class'];

    $offset += 4;
  }

  $ret['answers'] = [];
  for ($i = 0; $i < $ret['answerRRs']; $i++) {
    $ret['answers'][$i] = [
      'label' => substr($body, $offset, 2),
      'type' => 0,
      'class' => 0,
      'ttl' => 0,
      'address' => '',
    ];

    $offset += 2;
    $params = unpack('ntype/nclass/Nttl/nlen', $body, $offset);

    $ret['answers'][$i]['type'] = $params['type'];
    $ret['answers'][$i]['class'] = $params['class'];
    $ret['answers'][$i]['ttl'] = $params['ttl'];

    $offset += 10;

    $ret['answers'][$i]['address'] = inet_ntop(substr($body, $offset, $params['len']));

    $offset += $params['len'];
  }

  return $ret;
}

function parseTCPSegment(string $body): array {
  $ret = unpack('nsrcPort/ndstPort/NseqNum/NackNum/nword7/nwinSize/nchecksum/nurgent', $body);

  $ret['offset'] = ($ret['word7'] >> 12) * 4;
  $ret['flags'] = $ret['word7'] & 0x01FF;
  unset($ret['word7']);

  $ret['flags'] = [
    'ns'  => ($ret['flags'] & 0b100000000) ? true : false,
    'cwr' => ($ret['flags'] & 0b010000000) ? true : false,
    'ece' => ($ret['flags'] & 0b001000000) ? true : false,
    'urg' => ($ret['flags'] & 0b000100000) ? true : false,
    'ack' => ($ret['flags'] & 0b000010000) ? true : false,
    'psh' => ($ret['flags'] & 0b000001000) ? true : false,
    'rst' => ($ret['flags'] & 0b000000100) ? true : false,
    'syn' => ($ret['flags'] & 0b000000010) ? true : false,
    'fin' => ($ret['flags'] & 0b000000001) ? true : false,
  ];

  $ret['options'] = substr($body, 20, $ret['offset'] - 20);
  $ret['data'] = substr($body, $ret['offset']);

  return $ret;
}

function formatEtherAddr(string $bin): string {
  $ret = [];
  $len = strlen($bin);

  for ($i = 0; $i < $len; $i++) {
    $ret[] = sprintf('%02x', ord($bin[$i]));
  }

  return implode(':', $ret);
}

function encodeEtherAddr(string $addr): string {
  $ret = '';

  $bytes = explode(':', $addr);

  foreach ($bytes as $byte) {
    $ret .= chr(hexdec($byte));
  }

  return $ret;
}

function getRoutingTable(): ?array {
  $fp = fopen('/proc/net/route', 'r');

  if (!$fp) {
    return null;
  }

  $ret = [];

  $header = preg_split("/[\s]+/", fgets($fp));

  while ($entry = fgets($fp)) {
    $record = preg_split("/[\s]+/", $entry);

    foreach ($header as $k => $v) {
      $record[$v] = $record[$k];
      unset($record[$k]);
    }

    $ret[] = $record;
  }

  return $ret;
}

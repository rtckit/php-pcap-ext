/*
  pcap extension for PHP (c) 2020 Ciprian Dosoftei
  This code is licensed under the MIT license (see LICENSE for details)
*/

#ifndef PHP_PCAP_H
# define PHP_PCAP_H

extern zend_module_entry pcap_module_entry;
# define phpext_pcap_ptr &pcap_module_entry

# define PHP_PCAP_VERSION "0.6.2"

# if defined(ZTS) && defined(COMPILE_DL_PCAP)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#include <pcap.h>

typedef struct pcap_pkthdr_32bit {
  u_int32_t ts_sec;
  u_int32_t ts_usec;
  u_int32_t caplen;
  u_int32_t len;
} pcap_pkthdr_32bit_t;

typedef struct pcap_capture_session {
  char *dev;
  int snaplen;
  int promisc;
  pcap_t *pcap;
  char errbuf[PCAP_ERRBUF_SIZE + 1];
  struct pcap_pkthdr_32bit header32;
  struct pcap_pkthdr *header;
  const u_char *data;
  int header_bytes;
  int data_bytes;
  char immediate;
  char non_blocking;
  long timeout;
  char *filter;
  php_stream_context *context;
  int fd;
} pcap_capture_session_t;

#endif	/* PHP_PCAP_H */

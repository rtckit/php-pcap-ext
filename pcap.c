/*
  pcap extension for PHP (c) 2020 Ciprian Dosoftei
  This code is licensed under the MIT license (see LICENSE for details)
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "php_pcap.h"
#include <Zend/zend_interfaces.h>
#include <pcap.h>

void pcap_close_session(pcap_capture_session_t *sess)
{
  if (sess->pcap) {
    pcap_close(sess->pcap);
  }

  efree(sess->dev);

  if (sess->filter) {
    efree(sess->filter);
  }

  efree(sess);
}

pcap_capture_session_t * pcap_activate_session(pcap_capture_session_t *sess)
{
  if (sess->context) {
    zval *tmpzval;

    if (
      ((tmpzval = php_stream_context_get_option(sess->context, "pcap", "snaplen")) != NULL) &&
      (Z_TYPE_P(tmpzval) == IS_LONG)
    ) {
      sess->snaplen = (int) zval_get_long(tmpzval);
    }

    if (
      ((tmpzval = php_stream_context_get_option(sess->context, "pcap", "promisc")) != NULL) &&
      ((Z_TYPE_P(tmpzval) == IS_TRUE) || (Z_TYPE_P(tmpzval) == IS_FALSE))
    ) {
      sess->promisc = (Z_TYPE_P(tmpzval) == IS_TRUE) ? 1 : 0;
    }

    if (
      ((tmpzval = php_stream_context_get_option(sess->context, "pcap", "immediate")) != NULL) &&
      ((Z_TYPE_P(tmpzval) == IS_TRUE) || (Z_TYPE_P(tmpzval) == IS_FALSE))
    ) {
      sess->immediate = (Z_TYPE_P(tmpzval) == IS_TRUE) ? 1 : 0;
    }

    if (
      ((tmpzval = php_stream_context_get_option(sess->context, "pcap", "blocking")) != NULL) &&
      ((Z_TYPE_P(tmpzval) == IS_TRUE) || (Z_TYPE_P(tmpzval) == IS_FALSE))
    ) {
      sess->non_blocking = (Z_TYPE_P(tmpzval) == IS_TRUE) ? 0 : 1;
    }

    if (
      ((tmpzval = php_stream_context_get_option(sess->context, "pcap", "timeout")) != NULL) &&
      (Z_TYPE_P(tmpzval) == IS_DOUBLE)
    ) {
      sess->timeout = (int) (zval_get_double(tmpzval) * 1000);
    }

    if (
      ((tmpzval = php_stream_context_get_option(sess->context, "pcap", "filter")) != NULL) &&
      (Z_TYPE_P(tmpzval) == IS_STRING)
    ) {
      sess->filter = emalloc(strlen(Z_STRVAL_P(tmpzval)) + 1);
      strcpy(sess->filter, Z_STRVAL_P(tmpzval));
    }
  }

  sess->pcap = pcap_create(sess->dev, sess->errbuf);
  if (sess->pcap == NULL) {
    php_error_docref(NULL, E_WARNING, "Cannot initiate capture on device %s: %s", sess->dev, sess->errbuf);

    pcap_close_session(sess);

    return NULL;
  }

  if (pcap_set_snaplen(sess->pcap, sess->snaplen) < 0) {
    php_error_docref(NULL, E_WARNING, "Cannot set snapshot length %d on device %s", sess->snaplen, sess->dev);

    pcap_close_session(sess);

    return NULL;
  }

  if (sess->promisc && (pcap_set_promisc(sess->pcap, sess->promisc) < 0)) {
    php_error_docref(NULL, E_WARNING, "Cannot set promiscuous mode %d on device %s", sess->promisc, sess->dev);

    pcap_close_session(sess);

    return NULL;
  }

  if (sess->immediate && (pcap_set_immediate_mode(sess->pcap, sess->immediate) < 0)) {
    php_error_docref(NULL, E_WARNING, "Cannot set immediate mode %d on device %s", sess->immediate, sess->dev);

    pcap_close_session(sess);

    return NULL;
  }

  if (pcap_set_timeout(sess->pcap, sess->timeout) < 0) {
    php_error_docref(NULL, E_WARNING, "Cannot set timeout %ldms on device %s", sess->timeout, sess->dev);

    pcap_close_session(sess);

    return NULL;
  }

  if (sess->non_blocking && (pcap_setnonblock(sess->pcap, sess->non_blocking, sess->errbuf) < 0)) {
    php_error_docref(NULL, E_WARNING, "Cannot set blocking option on device %s: %s", sess->dev, sess->errbuf);

    pcap_close_session(sess);

    return NULL;
  }

  if (pcap_activate(sess->pcap) < 0) {
    php_error_docref(NULL, E_WARNING, "Cannot activate live capture on device %s: %s", sess->dev, pcap_geterr(sess->pcap));

    pcap_close_session(sess);

    return NULL;
  }

  if (sess->filter && strlen(sess->filter)) {
    struct bpf_program fp;

    if (pcap_compile(sess->pcap, &fp, sess->filter, 0, PCAP_NETMASK_UNKNOWN) < 0) {
      php_error_docref(NULL, E_WARNING, "Cannot parse filter '%s' on device %s: %s", sess->filter, sess->dev, pcap_geterr(sess->pcap));

      pcap_close_session(sess);

      return NULL;
    }

    if (pcap_setfilter(sess->pcap, &fp) < 0) {
      php_error_docref(NULL, E_WARNING, "Cannot install filter '%s' on device %s: %s", sess->filter, sess->dev, pcap_geterr(sess->pcap));

      pcap_close_session(sess);

      return NULL;
    }
  }

  return sess;
}

static ssize_t php_pcap_stream_write(php_stream *stream, const char *buf, size_t count)
{
  pcap_capture_session_t *sess = (pcap_capture_session_t *) stream->abstract;
  ssize_t writestate = 0;

  if (!sess->pcap && !pcap_activate_session(sess)) {
    return -1;
  }

  writestate = pcap_inject(sess->pcap, buf, count);

  if (writestate == PCAP_ERROR) {
    php_error_docref(NULL, E_WARNING, "Cannot write to device %s: %s", sess->dev, pcap_geterr(sess->pcap));
  }

  return writestate;
}

static ssize_t php_pcap_stream_read(php_stream *stream, char *buf, size_t count)
{
  pcap_capture_session_t *sess = (pcap_capture_session_t *) stream->abstract;
  ssize_t readstate = 0;

  if (!sess->pcap && !pcap_activate_session(sess)) {
    return -1;
  }

  int ret = 0, remainder = count, offset = 0, length = 0;

  while(1) {
    if (!sess->header_bytes && !sess->data_bytes) {
      ret = pcap_next_ex(sess->pcap, &sess->header, &sess->data);

      if (!ret) {
        sess->header_bytes = 0;
        sess->data_bytes = 0;

        break;
      }

      if (ret == PCAP_ERROR) {
        php_error_docref(NULL, E_WARNING, "Cannot read from device %s: %s", sess->dev, pcap_geterr(sess->pcap));

        sess->header_bytes = 0;
        sess->data_bytes = 0;

        break;
      }

      sess->header32.ts_sec = (u_int32_t) sess->header->ts.tv_sec;
      sess->header32.ts_usec = (u_int32_t) sess->header->ts.tv_usec;
      sess->header32.caplen = sess->header->caplen;
      sess->header32.len = sess->header->len;

      sess->header_bytes = sizeof(pcap_pkthdr_32bit_t);
      sess->data_bytes = sess->header->caplen;
    }

    offset = sizeof(pcap_pkthdr_32bit_t) - sess->header_bytes;
    length = (remainder < sess->header_bytes) ? remainder : sess->header_bytes;

    memcpy(buf + readstate, &sess->header32 + offset, length);
    readstate += length;
    remainder -= length;
    sess->header_bytes -= length;

    offset = sess->header->caplen - sess->data_bytes;
    length = (remainder < sess->data_bytes) ? remainder : sess->data_bytes;

    memcpy(buf + readstate, sess->data + offset, length);
    readstate += length;
    remainder -= length;
    sess->data_bytes -= length;

    if (!remainder) {
      break;
    }
  }

  return readstate;
}

static int php_pcap_stream_close(php_stream *stream, int close_handle)
{
  pcap_capture_session_t *sess = (pcap_capture_session_t *) stream->abstract;

  pcap_close_session(sess);

  return 0;
}

static int php_pcap_stream_cast(php_stream *stream, int castas, void **ret)
{
  pcap_capture_session_t *sess = (pcap_capture_session_t *) stream->abstract;
  int fd = 0;

  if (!sess->pcap && !pcap_activate_session(sess)) {
    return FAILURE;
  }

  switch (castas) {
    case PHP_STREAM_AS_FD_FOR_SELECT:
    case PHP_STREAM_AS_FD:
    case PHP_STREAM_AS_SOCKETD:
      fd = pcap_get_selectable_fd(sess->pcap);

      if (fd < 0) {
        return FAILURE;
      }

      if (ret) {
        *(int *) ret = fd;
      }

      return SUCCESS;
  }

  return FAILURE;
}

static int php_pcap_stream_set_option(php_stream *stream, int option, int value, void *ptrparam)
{
  pcap_capture_session_t *sess = (pcap_capture_session_t *) stream->abstract;
  int ret = -1;

  switch (option) {
    case PHP_STREAM_OPTION_BLOCKING:
      if (sess->pcap && pcap_setnonblock(sess->pcap, !value, sess->errbuf) == PCAP_ERROR) {
        php_error_docref(NULL, E_WARNING, "Cannot set blocking option: %s", sess->errbuf);
      } else {
        ret = !sess->non_blocking;
        sess->non_blocking = !value;
      }
      break;

    case PHP_STREAM_OPTION_READ_TIMEOUT:
      sess->timeout = ((struct timeval *) ptrparam)->tv_sec * 1000 + (((struct timeval *) ptrparam)->tv_usec / 1000);

      if (sess->pcap && (pcap_set_timeout(sess->pcap, sess->timeout) == PCAP_ERROR_ACTIVATED)) {
        php_error_docref(NULL, E_WARNING, "Cannot set timeout option on active session: %s", sess->errbuf);
      } else {
        ret = sess->timeout;
      }
      break;
  }

  return ret;
}

php_stream_ops php_pcap_stream_ops = {
  php_pcap_stream_write,
  php_pcap_stream_read,
  php_pcap_stream_close,
  NULL,
  NULL,
  NULL,
  php_pcap_stream_cast,
  NULL,
  php_pcap_stream_set_option,
};

/* {{{ php_pcap_fopen
 * pcap:// fopen wrapper
 */
static php_stream *php_pcap_fopen(
  php_stream_wrapper *wrapper,
  const char *path,
  const char *mode,
  int options,
  zend_string **opened_path,
  php_stream_context *context STREAMS_DC
)
{
  php_url *parsed_url = php_url_parse(path);
  pcap_if_t* alldevsp = NULL;

  if (!parsed_url->scheme) {
    php_error_docref(NULL, E_WARNING, "Missing scheme, should be 'pcap'");
    php_url_free(parsed_url);

    return NULL;
  }

  if (strcmp(parsed_url->scheme->val, "pcap")) {
    php_error_docref(NULL, E_WARNING, "Unsupported scheme: %s", parsed_url->scheme->val);
    php_url_free(parsed_url);

    return NULL;
  }

  if (parsed_url->path && strcmp(parsed_url->path->val, "/")) {
    php_error_docref(NULL, E_WARNING, "Unsupported path: %s", parsed_url->path->val);
    php_url_free(parsed_url);

    return NULL;
  }

  if (parsed_url->query) {
    php_error_docref(NULL, E_WARNING, "Unsupported query: %s", parsed_url->query->val);
    php_url_free(parsed_url);

    return NULL;
  }

  pcap_capture_session_t *sess = emalloc(sizeof(pcap_capture_session_t));
  sess->dev = emalloc(strlen(parsed_url->host->val) + 1);
  strcpy(sess->dev, parsed_url->host->val);
  sess->snaplen = BUFSIZ;
  sess->promisc = 0;
  sess->pcap = NULL;
  sess->header = NULL;
  sess->data = NULL;
  sess->header_bytes = 0;
  sess->data_bytes = 0;
  sess->immediate = 0;
  sess->non_blocking = 0;
  sess->timeout = 1000;
  sess->filter = NULL;
  sess->context = context;

  php_url_free(parsed_url);

  if (pcap_findalldevs(&alldevsp, sess->errbuf)) {
    php_error_docref(NULL, E_WARNING, "Cannot enumerate network devices: %s", sess->errbuf);
    pcap_close_session(sess);

    return NULL;
  }

  pcap_if_t *dev = alldevsp;
  char found = 0;

  while (dev) {
    if (!strcmp(sess->dev, dev->name)) {
      found = 1;
      break;
    }

    dev = dev->next;
  }

  pcap_freealldevs(alldevsp);

  if (!found) {
    php_error_docref(NULL, E_WARNING, "Unknown device: %s", sess->dev);
    pcap_close_session(sess);

    return NULL;
  }

  php_stream *stream = php_stream_alloc(&php_pcap_stream_ops, sess, 0, mode);

  return stream;
}
/* }}} */

static php_stream_wrapper_ops php_pcap_stream_wrapper_wops = {
  php_pcap_fopen,
  NULL,
  NULL,
  NULL,
  NULL,
  "pcap"
};

php_stream_wrapper php_pcap_stream_wrapper = {
  &php_pcap_stream_wrapper_wops,
  NULL,
  0
};

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(pcap)
{
  if (php_register_url_stream_wrapper("pcap", &php_pcap_stream_wrapper) != SUCCESS) {
    php_error_docref(NULL, E_ERROR, "Cannot register pcap stream wrapper");

    return FAILURE;
  }

  return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(pcap)
{
  if (php_unregister_url_stream_wrapper("pcap") != SUCCESS) {
    php_error_docref(NULL, E_ERROR, "Cannot unregister pcap stream wrapper");

    return FAILURE;
  }

  return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(pcap)
{
  php_info_print_table_start();

  php_info_print_table_header(2, "pcap support", "enabled");
  php_info_print_table_header(2, "libpcap version", pcap_lib_version());

  php_info_print_table_end();
}
/* }}} */

/* {{{ pcap_functions[]
 */
static const zend_function_entry pcap_functions[] = {
  PHP_FE_END
};
/* }}} */

/* {{{ pcap_module_entry
 */
zend_module_entry pcap_module_entry = {
  STANDARD_MODULE_HEADER,
  "pcap",
  pcap_functions,
  PHP_MINIT(pcap),
  PHP_MSHUTDOWN(pcap),
  NULL,
  NULL,
  PHP_MINFO(pcap),
  PHP_PCAP_VERSION,
  STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_PCAP
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(pcap)
#endif

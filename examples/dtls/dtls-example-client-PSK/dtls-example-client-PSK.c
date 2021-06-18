/*Lots of parts are copied from the mbedtls dtls client example*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#define MBEDTLS_DEBUG_C

#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"
#include "mbedtls/debug.h"

#define SERVER_PORT 4433
#define SERVER_NAME "localhost"

#define SERVER_ADDR "::1"

#define MESSAGE "Echo this"

#define READ_TIMEOUT_MS 1000
#define MAX_RETRY 5

#define DEBUG_LEVEL 0

const unsigned char psk[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const char psk_id[] = "Client_identity";

PROCESS(dtls_example_client, "DTLS Example Client");
AUTOSTART_PROCESSES(&dtls_example_client);

static void
my_debug(void *ctx, int level,
         const char *file, int line,
         const char *str)
{
  ((void)level);
  ((void)ctx);

  printf("%s:%04d: %s", file, line, str);
}
PROCESS_THREAD(dtls_example_client, ev, data)
{

  static int ret, len;
  static struct udp_socket sock;
  unsigned char buf[1024];
  const char *pers = "dtls_client";
  static int retry_left = MAX_RETRY;

  static mbedtls_entropy_context entropy;
  static mbedtls_ctr_drbg_context ctr_drbg;
  static mbedtls_ssl_context ssl;
  static mbedtls_ssl_config conf;
  static mbedtls_timing_delay_context timer;

  PROCESS_BEGIN();
  printf("Starting DTLS PSK Example Client\n");
  udp_socket_register(&sock, NULL, mbedtls_callback);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

  printf("\n  . Seeding the random number generator...");

  mbedtls_entropy_init(&entropy);
  if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char *)pers,
                                  strlen(pers))) != 0) {
    printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    goto exit;
  }

  printf("ok\n");

  printf("  . Connecting to udp/%s/%d...", SERVER_NAME, SERVER_PORT);

  uip_ipaddr_t server_addr;

  uip_ip6addr(&server_addr, 0xfd00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);

  if((ret = udp_socket_connect(&sock, &server_addr,
                               SERVER_PORT)) != 1) {
    printf(" failed\n  ! udp_socket_connect returned %d\n\n", ret);
    goto exit;
  }

  printf(" ok\n");

  printf("  . Setting up the DTLS structure...");

  if((ret = mbedtls_ssl_config_defaults(&conf,
                                        MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
    goto exit;
  }

  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_psk(&conf, psk, sizeof(psk), (const unsigned char *)psk_id, sizeof(psk_id) - 1);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
  mbedtls_ssl_conf_max_frag_len(&conf, MBEDTLS_SSL_MAX_FRAG_LEN_1024);

  if((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    printf(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", (unsigned int)-ret);
    goto exit;
  }

  if((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0) {
    printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
    goto exit;
  }
  mbedtls_ssl_set_bio(&ssl, &sock,
                      mbedtls_net_send, mbedtls_net_recv, NULL);

  mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  printf(" ok\n");

  mbedtls_ssl_set_mtu(&ssl, UIP_CONF_BUFFER_SIZE);

  printf("  . Performing the DTLS handshake...");

  static struct etimer et;

  do{

    ret = mbedtls_ssl_handshake(&ssl);
    if(ret == MBEDTLS_ERR_SSL_WANT_READ) {

      etimer_set(&et, (CLOCK_SECOND * timer.fin_ms) / 1000);

      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et) || ev == PROCESS_EVENT_POLL);

      etimer_stop(&et);
    }
  }while(ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if(ret != 0) {
    printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int)-ret);
    goto exit;
  }

  printf(" ok\n");

send_request:
  printf("  > Write to server:");

  len = sizeof(MESSAGE) - 1;

  do{
    ret = mbedtls_ssl_write(&ssl, (unsigned char *)MESSAGE, len);
  }while(ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if(ret < 0) {
    printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
    goto exit;
  }

  len = ret;
  printf(" %d bytes written\n\n%s\n\n", len, MESSAGE);

  /*
   * 7. Read the echo response
   */
  printf("  < Read from server:");

  len = sizeof(buf) - 1;
  memset(buf, 0, sizeof(buf));

  do{
    ret = mbedtls_ssl_read(&ssl, buf, len);
    if(ret == MBEDTLS_ERR_SSL_WANT_READ) {

      etimer_set(&et, (CLOCK_SECOND * timer.fin_ms) / 1000);

      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et) || ev == PROCESS_EVENT_POLL);

      etimer_stop(&et);
    }
  }while(ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if(ret <= 0) {
    switch(ret) {
    case MBEDTLS_ERR_SSL_TIMEOUT:
      printf(" timeout\n\n");
      if(retry_left-- > 0) {
        goto send_request;
      }
      goto exit;

    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      printf(" connection was closed gracefully\n");
      ret = 0;
      goto close_notify;

    default:
      printf(" mbedtls_ssl_read returned -0x%x\n\n", (unsigned int)-ret);
      goto exit;
    }
  }

  len = ret;
  buf[len] = '\0';
  printf(" %d bytes read\n\n%s\n\n", len, buf);

  /*
   * 8. Done, cleanly close the connection
   */
close_notify:
  printf("  . Closing the connection...");

  /* No error checking, the connection might be closed already */
  do{
    ret = mbedtls_ssl_close_notify(&ssl);
  }while(ret == MBEDTLS_ERR_SSL_WANT_WRITE);
  ret = 0;

  printf(" done\n");

  /*
   * 9. Final clean-ups and exit
   */

exit:
  udp_socket_close(&sock);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  /* Shell can not handle large exit numbers -> 1 for errors */
  if(ret < 0) {
    ret = 1;
  }

  exit(EXIT_SUCCESS);
  PROCESS_END();
}
/*#endif*/

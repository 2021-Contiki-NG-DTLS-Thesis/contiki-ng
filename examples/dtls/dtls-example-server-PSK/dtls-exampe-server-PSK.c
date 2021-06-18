
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
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_time_t     time_t
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#include "contiki.h"

const unsigned char psk[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const char psk_id[] = "Client_identity";

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP

#define READ_TIMEOUT_MS 10000   /* 5 seconds */
#define DEBUG_LEVEL 0

static void
my_debug(void *ctx, int level,
         const char *file, int line,
         const char *str)
{
  ((void)level);

  mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
  fflush((FILE *)ctx);
}
PROCESS(dtls_example_server, "DTLS Example Server");
AUTOSTART_PROCESSES(&dtls_example_server);

PROCESS_THREAD(dtls_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  LOG_INFO("Starting MbedTLS Example Server\n");

  while(1) {

    static int ret, len;
    static struct udp_socket listen_sock;
    static unsigned char buf[1024];
    static const char *pers = "dtls_server";
    static mbedtls_ssl_cookie_ctx cookie_ctx;

    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static mbedtls_ssl_context ssl;
    static mbedtls_ssl_config conf;
    /*static mbedtls_x509_crt srvcert; */
    static mbedtls_pk_context pkey;
    static mbedtls_timing_delay_context timer;
    static struct etimer et;

#if defined(MBEDTLS_SSL_CACHE_C)
    static mbedtls_ssl_cache_context cache;
#endif

    udp_socket_register(&listen_sock, NULL, mbedtls_callback);

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_cookie_init(&cookie_ctx);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache);
#endif

    /* mbedtls_x509_crt_init( &srvcert ); */
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 2. Setup the "listening" UDP socket
     */
    printf("  . Bind on udp/*/4433 ...");
    fflush(stdout);

    if((ret = udp_socket_bind(&listen_sock, 4433) != 1)) {
      printf(" failed\n  ! udp_socket_bind returned %d\n\n", ret);
      goto exit;
    }

    printf(" ok\n");

    /*
     * 3. Seed the RNG
     */
    printf("  . Seeding the random number generator...");
    fflush(stdout);

    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers,
                                    strlen(pers))) != 0) {
      printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
      goto exit;
    }

    printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    printf("  . Setting up the DTLS data...");
    fflush(stdout);

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_SERVER,
                                          MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
      mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
      goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_ssl_conf_psk(&conf, psk, sizeof(psk), (const unsigned char *)psk_id, sizeof(psk_id) - 1);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    if((ret = mbedtls_ssl_cookie_setup(&cookie_ctx,
                                       mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
      printf(" failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret);
      goto exit;
    }

    mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                  &cookie_ctx);

    if((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
      printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
      goto exit;
    }

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if(ret != 0) {
      char error_buf[100];
      mbedtls_strerror(ret, error_buf, 100);
      printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    PROCESS_YIELD();

    /* For HelloVerifyRequest cookies */
    if((ret = mbedtls_ssl_set_client_transport_id(&ssl,
                                                  (unsigned char *)&listen_sock.udp_conn, sizeof(listen_sock.udp_conn))) != 0) {
      printf(" failed\n  ! "
             "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", (unsigned int)-ret);
      goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &listen_sock,
                        mbedtls_net_sendto, mbedtls_net_recv, NULL);

    printf(" ok\n");

    mbedtls_ssl_set_mtu(&ssl, UIP_CONF_BUFFER_SIZE);

    /*
     * 5. Handshake
     */
    printf("  . Performing the DTLS handshake...");
    fflush(stdout);

    do{
      ret = mbedtls_ssl_handshake(&ssl);
      if(ret == MBEDTLS_ERR_SSL_WANT_READ) {

        etimer_set(&et, (CLOCK_SECOND * timer.fin_ms) / 1000);

        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et) || ev == PROCESS_EVENT_POLL);

        etimer_stop(&et);
      }
    }while(ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if(ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
      printf(" hello verification requested\n");
      ret = 0;
      goto reset;
    } else if(ret != 0) {
      printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int)-ret);
      goto reset;
    }

    printf(" ok\n");

    /*
     * 6. Read the echo Request
     */
    printf("  < Read from client:");
    fflush(stdout);

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
        goto reset;

      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        printf(" connection was closed gracefully\n");
        ret = 0;
        goto close_notify;

      default:
        printf(" mbedtls_ssl_read returned -0x%x\n\n", (unsigned int)-ret);
        goto reset;
      }
    }

    len = ret;
    printf(" %d bytes read\n\n%s\n\n", len, buf);

    /*
     * 7. Write the 200 Response
     */
    printf("  > Write to client:");
    fflush(stdout);

    do{
      ret = mbedtls_ssl_write(&ssl, buf, len);
    }while(ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if(ret < 0) {
      printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
      goto exit;
    }

    len = ret;
    printf(" %d bytes written\n\n%s\n\n", len, buf);

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

    goto reset;

    /*
     * Final clean-ups and exit
     */
exit:
#ifdef MBEDTLS_ERROR_C
    if(ret != 0) {
      char error_buf[100];
      mbedtls_strerror(ret, error_buf, 100);
      printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    udp_socket_close(&listen_sock);

    /*mbedtls_x509_crt_free( &srvcert ); */
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_cookie_free(&cookie_ctx);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&cache);
#endif

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
    printf("  Press Enter to exit this program.\n");
    fflush(stdout);
    getchar();
#endif

    /* Shell can not handle large exit numbers -> 1 for errors */
    if(ret < 0) {
      ret = 1;
    }

    mbedtls_exit(ret);
    break;
  }

  PROCESS_END();
}

/*#endif  MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_DTLS &&
          MBEDTLS_SSL_COOKIE_C && MBEDTLS_NET_C && MBEDTLS_ENTROPY_C &&
    MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_RSA_C
    && MBEDTLS_CERTS_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_TIMING_C */

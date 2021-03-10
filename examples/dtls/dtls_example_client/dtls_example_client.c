/*Lots of parts are copied from the mbedtls dtls client example*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"


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


#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_APP

#if !defined(MBEDTLS_SSL_CLI_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) ||    \
    !defined(MBEDTLS_NET_C)  || !defined(MBEDTLS_TIMING_C) ||             \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) ||        \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_RSA_C) ||      \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
    printf( "MBEDTLS_SSL_CLI_C and/or MBEDTLS_SSL_PROTO_DTLS and/or "
            "MBEDTLS_NET_C and/or MBEDTLS_TIMING_C and/or "
            "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
            "MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_RSA_C and/or "
            "MBEDTLS_CERTS_C and/or MBEDTLS_PEM_PARSE_C not defined.\n" );
    mbedtls_exit( 0 );
}
#else

#include <string.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"


#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"

#define SERVER_ADDR "::1"

#define MESSAGE "Echo this"

#define READ_TIMEOUT_MS 1000
#define MAX_RETRY 5

#define DEBUG_LEVEL 0

PROCESS(dtls_example_server, "DTLS Example Server");
AUTOSTART_PROCESSES(&dtls_example_server);

PROCESS_THREAD(dtls_example_server, ev, data)
{
  PROCESS_BEGIN();

  PROCESS_PAUSE();

  printf("Starting DTLS Example Server\n");

  int ret, len;
  mbedtls_net_context server_fd;
  uint32_t flags;
  unsigned char buf[1024];
  const char *pers = "dtls_client";
  int retry_left = MAX_RETRY;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  mbedtls_timing_delay_context timer;

  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  printf("\n  . Seeding the random number generator...");
  
  mbedtls_entropy_init( &entropy );
  if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                             (const unsigned char *) pers,
                             strlen( pers ) ) ) != 0 )
  {
    printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    goto exit;
  }

  printf("ok\n");



  printf("  . Loading the CA root certificate ...");

  ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem,
                        mbedtls_test_cas_pem_len);

  if( ret < 0 )
  {
    printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int) -ret );
    goto exit;
  }

  printf( " ok (%d skipped)\n", ret );




  printf( "  . Connecting to udp/%s/%s...", SERVER_NAME, SERVER_PORT );

  if( ( ret = mbedtls_net_connect( &server_fd, SERVER_ADDR,
                                      SERVER_PORT, MBEDTLS_NET_PROTO_UDP ) ) != 0 )
  {
    printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
    goto exit;
  }

  printf( " ok\n" );




  printf( "  . Setting up the DTLS structure..." );

  if( ( ret = mbedtls_ssl_config_defaults( &conf,
                MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
  {
    printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
    goto exit;
  }

  mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
  mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
  mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
//  mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

  if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
  {
    printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
    goto exit;
  }

  if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
  {
    printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
    goto exit;
  }
  mbedtls_ssl_set_bio( &ssl, &server_fd,
                        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );

  mbedtls_ssl_set_timer_cb( &ssl, &timer, mbedtls_timing_set_delay,
                                          mbedtls_timing_get_delay );

  printf( " ok\n" );


  printf( "  . Performing the DTLS handshake..." );

  do ret = mbedtls_ssl_handshake( &ssl );
  while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
       ret == MBEDTLS_ERR_SSL_WANT_WRITE );

  if( ret != 0 )
  {
    printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret );
    goto exit;
  }

  printf( " ok\n" );

  /*
   * 5. Verify the server certificate
   */
  printf( "  . Verifying peer X.509 certificate..." );

  /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
   * handshake would not succeed if the peer's cert is bad.  Even if we used
   * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
  if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
  {
    char vrfy_buf[512];

    printf( " failed\n" );

    mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

    printf( "%s\n", vrfy_buf );
  }
  else
    printf( " ok\n" );

send_request:
  printf( "  > Write to server:" );

  len = sizeof( MESSAGE ) - 1;

  do ret = mbedtls_ssl_write( &ssl, (unsigned char *) MESSAGE, len );
  while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE );

  if( ret < 0 )
  {
    printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
    goto exit;
  }

  len = ret;
  printf( " %d bytes written\n\n%s\n\n", len, MESSAGE );

    /*
     * 7. Read the echo response
     */
  printf( "  < Read from server:" );

  len = sizeof( buf ) - 1;
  memset( buf, 0, sizeof( buf ) );

  do ret = mbedtls_ssl_read( &ssl, buf, len );
  while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
         ret == MBEDTLS_ERR_SSL_WANT_WRITE );

  if( ret <= 0 )
  {
    switch( ret )
    {
      case MBEDTLS_ERR_SSL_TIMEOUT:
        printf( " timeout\n\n" );
        if( retry_left-- > 0 )
          goto send_request;
        goto exit;

      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        printf( " connection was closed gracefully\n" );
        ret = 0;
        goto close_notify;

      default:
        printf( " mbedtls_ssl_read returned -0x%x\n\n", (unsigned int) -ret );
        goto exit;
    }
  }

  len = ret;
  printf( " %d bytes read\n\n%s\n\n", len, buf );

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
  printf( "  . Closing the connection..." );

  /* No error checking, the connection might be closed already */
  do ret = mbedtls_ssl_close_notify( &ssl );
  while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
  ret = 0;

  printf( " done\n" );

    /*
     * 9. Final clean-ups and exit
     */

    
exit:
  mbedtls_net_free( &server_fd );

  mbedtls_x509_crt_free( &cacert );
  mbedtls_ssl_free( &ssl );
  mbedtls_ssl_config_free( &conf );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );


  /* Shell can not handle large exit numbers -> 1 for errors */
  if( ret < 0 )
      ret = 1;

  PROCESS_END();

}
#endif
CONTIKI_PROJECT = dtls_example_server


all: $(CONTIKI_PROJECT)

PLATFORMS_EXCLUDE = sky z1

CONTIKI=../../..


include $(CONTIKI)/Makefile.dir-variables

MBEDTLS_PATH:=os/net/security/mbedtls

#ifeq (${wildcard $(CONTIKI)/$(MBEDTLS_PATH)/Makefile},)
#	${error Could not find the  Mbed TLS submodule. Please run "git submodule update --init" and try again}
#endif

CFLAGS += -DWITH_DTLS=1

MODULES += $(MBEDTLS_PATH) ${addprefix $(MBEDTLS_PATH)/,library include}



include $(CONTIKI)/Makefile.include

CONTIKI_PROJECT = dtls_example_server


all: $(CONTIKI_PROJECT)

PLATFORMS_EXCLUDE = sky z1

CONTIKI=../../..


include $(CONTIKI)/Makefile.dir-variables

MBEDTLS_PATH:=../../../os/net/security/mbedtls

#ifeq (${wildcard $(CONTIKI)/$(MBEDTLS_PATH)/Makefile},)
#	${error Could not find the  Mbed TLS submodule. Please run "git submodule update --init" and try again}
#endif


CFLAGS+=-I${addprefix $(MBEDTLS_PATH)/,include}

TARGET_LIBFILES+=-L${addprefix $(MBEDTLS_PATH)/, library}
TARGET_LIBFILES+=-lmbedtls -lmbedx509 -lmbedcrypto




include $(CONTIKI)/Makefile.include

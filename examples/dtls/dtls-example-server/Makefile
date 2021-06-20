CONTIKI_PROJECT = dtls-example-server


all: $(CONTIKI_PROJECT)

PLATFORMS_EXCLUDE = sky z1

CONTIKI=../../..


include $(CONTIKI)/Makefile.dir-variables

MBEDTLS_PATH:=os/net/security/mbedtls

CFLAGS += -DWITH_DTLS=1

MODULES += $(MBEDTLS_PATH) ${addprefix $(MBEDTLS_PATH)/,library include}



include $(CONTIKI)/Makefile.include
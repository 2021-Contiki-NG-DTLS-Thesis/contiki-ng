CONTIKI_PROJECT = dtls_example_client_PSK

all: $(CONTIKI_PROJECT)

PLATFORMS_EXCLUDE = sky z1

CONTIKI=../../..

include $(CONTIKI)/Makefile.dir-variables

MBEDTLS_PATH:=os/net/security/mbedtls


ifeq (${wildcard $(CONTIKI)/$(MBEDTLS_PATH)/Makefile},)
	${error Could not find the  Mbed TLS submodule. Please run "git submodule update --init" and try again}
endif

# asan flags are for address sanitization
CFLAGS += -DWITH_DTLS=1 -fsanitize=address -fsanitize=undefined -g -fsanitize=float-divide-by-zero -fsanitize=signed-integer-overflow #-fsanitize=implicit-conversion -fsanitize=local-bounds
CXXFLAGS += -fsanitize=address -fsanitize=undefined
LDFLAGS += -fsanitize=address -fsanitize=undefined -static-libasan


MODULES += $(MBEDTLS_PATH) ${addprefix $(MBEDTLS_PATH)/,library include}


include $(CONTIKI)/Makefile.include

#include $(CONTIKI)/$(MBEDTLS_PATH)/Makefile

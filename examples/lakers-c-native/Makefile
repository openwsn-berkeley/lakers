CC=gcc
CFLAGS=-Wall -I../../target/include -fsanitize=address,undefined,leak

TARGET=lakers_c_native

SRC=main.c

OBJ=$(SRC:.c=.o)

HOST_TRIPLE := $(shell rustc -vV | sed -n 's|host: ||p')

LIB_DIR=../../target/$(HOST_TRIPLE)/release/
LIB_NAME=lakers_c

ifeq ($(LAKERS_EAD), authz)
	CFLAGS += -DLAKERS_EAD_AUTHZ
endif

LDFLAGS=-fsanitize=address,undefined,leak

all: $(TARGET)

# rule for building the target executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -ggdb -O0 -o $@ $^ -L$(LIB_DIR) -l$(LIB_NAME) -lcoap-3

# rule for building object files
%.o: %.c
	$(CC) $(CFLAGS) -ggdb -c $<

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean

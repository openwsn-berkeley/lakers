CC=gcc
CFLAGS=-Wall -I../../target/include

TARGET=lakers_ffi_native

SRC=main.c

OBJ=$(SRC:.c=.o)

LIB_DIR=../../target/x86_64-unknown-linux-gnu/debug/
LIB_NAME=lakers_ffi

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

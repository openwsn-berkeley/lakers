# name of your application
APPLICATION = c-wrapper-riot

# If no BOARD is found in the environment, use this default:
BOARD ?= nrf52840dk

INCLUDES += -I$(CURDIR)/../../include
ARCHIVES += $(CURDIR)/../../target/thumbv7em-none-eabihf/release/libedhoc_rs.a

CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=16384 -DISR_STACKSIZE=16384

USEMODULE += od

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../../../RIOT

DEVELHELP ?= 1

include $(RIOTBASE)/Makefile.include

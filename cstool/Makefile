# Makefile for Cstool of Capstone Disassembly Engine

include ../functions.mk

.PHONY: clean all

CFLAGS += -I../include -I. $(CSTOOL_ARCH_FLAGS)
CFLAGS += -std=gnu99
LDFLAGS += -O3 -Wall

TARGET = cstool
SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)

LIBCAPSTONE = libcapstone.a

IS_CYGWIN := $(shell $(CC) -dumpmachine 2>/dev/null | grep -i cygwin | wc -l)
ifeq ($(IS_CYGWIN),1)
LIBCAPSTONE = capstone.lib
else
IS_MINGW := $(shell $(CC) --version 2>/dev/null | grep -i "\(mingw\|MSYS\)" | wc -l)
ifeq ($(IS_MINGW),1)
LIBCAPSTONE = capstone.lib
endif
endif

CSTOOL_LIBRARY ?= ../$(LIBCAPSTONE)

all: $(TARGET)

$(TARGET): $(CSTOOL_LIBRARY) $(OBJECTS)
ifeq ($(V), 0)
	$(call log,LINK,$@)
	@${CC} $(OBJECTS) "$(CSTOOL_LIBRARY)" $(LDFLAGS) -o $@
else
	${CC} $(OBJECTS) "$(CSTOOL_LIBRARY)" $(LDFLAGS) -o $@
endif

clean:
	${RM} -rf *.o $(TARGET)
	${RM} -f *.d

%.o: %.c
ifeq ($(V), 0)
	$(call log,CC,$@)
	@${CC} $(CFLAGS) -c $< -o $@
else
	${CC} $(CFLAGS) -c $< -o $@
endif

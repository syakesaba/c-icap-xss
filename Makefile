#!/usr/bin/env make
#encoding: utf-8

CC = g++
RM = rm -f
#CFLAGS = -O2 -g -MMD -MP -Wall -Wextra -Winit-self -Wno-missing-field-initializers -fPIC
CFLAGS = -fPIC
LDFLAGS = -lre2 -licapapi -luriparser -shared

TARGET = libc-icap-xss.so
LIBS =
SRCDIR = .
SRCS = $(shell find $(SRCDIR) -name "*.cpp")
#INCS = $(shell find $(SRCDIR) -name "*.h")
OBJS = $(SRCS:.cpp=.o)

.PHONY: all
all: $(TARGET)

.SUFFIXES: .cpp .o

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: clean
clean:
	-${RM} ${TARGET} ${OBJS}

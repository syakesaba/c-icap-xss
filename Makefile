#!/usr/bin/env make
#encoding: utf-8

CC = g++
RM = rm -f
#CFLAGS = -O2 -g -MMD -MP -Wall -Wextra -Winit-self -Wno-missing-field-initializers -fPIC
CFLAGS = -fPIC
LDFLAGS = -lre2 -licapapi -luriparser -shared

TARGET = libc-icap-xss.so
LIBS =
SRCDIR = src
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

#flow need graphviz
DOT := dot
DOT_TARGET := flow.dot
DOT_OPTIONS ?= -Tjpg

.PHONY: flow
flow: $(DOT_TARGET)
	$(DOT) $(DOT_OPTIONS) $(DOT_TARGET) -o $(DOT_TARGET:.dot=.jpg)

.PHONY: cleanflow
cleanflow:
	-$(RM) $(DOT_TARGET:.dot=.jpg)

#doc need doxygen
#DOXYGEN := doxygen
#DOXYFILE := c-icap-xss.Doxyfile
#DOXYGEN_TARGET_SRC := $(SRCDIR)
#DOXYGEN_TARGET := doc

#install:$(TARGET)
#$(TARGET): $(SOURCE)
#	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $< $(INCLUDES)

#doc: $(DOXYGEN_TARGET_SRC) $(DOXYFILE)
#	$(DOXYGEN) $(DOXYFILE)

#.PHONY: cleandoc
#cleandoc:
#	$(info not-impremented-yet)


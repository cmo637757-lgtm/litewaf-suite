CC ?= cc
PCRE2_CFLAGS ?= $(shell pcre2-config --cflags)
PCRE2_LIBS ?= $(shell pcre2-config --libs8)
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g
CPPFLAGS ?= -Iinclude $(PCRE2_CFLAGS)
LDFLAGS ?=
LDLIBS ?= $(PCRE2_LIBS)

BUILD_DIR := build
LIB := $(BUILD_DIR)/liblwaf_rule_engine.a
OBJ := $(BUILD_DIR)/lwaf_rule_engine.o
TEST := $(BUILD_DIR)/test_rule_engine
EVAL := $(BUILD_DIR)/lwaf_eval

.PHONY: all test clean

all: $(LIB) $(TEST) $(EVAL)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJ): src/lwaf_rule_engine.c include/lwaf_rule_engine.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJ)
	ar rcs $@ $<

$(TEST): tests/test_rule_engine.c $(LIB) include/lwaf_rule_engine.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_rule_engine.c $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

$(EVAL): tools/lwaf_eval.c $(LIB) include/lwaf_rule_engine.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tools/lwaf_eval.c $(LIB) $(LDFLAGS) $(LDLIBS) -o $@

test: $(TEST)
	$(TEST)

clean:
	rm -rf $(BUILD_DIR)

# Host-side unit tests. Builds main.c natively with PLATFORM_HOST, so no
# PS4/PS5 SDK is needed:  make -C tests
CC ?= cc
CFLAGS ?= -O1 -g
SANITIZE ?= -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
override CFLAGS += -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE -DPLATFORM_HOST=1

TEST_BIN := test_main

all: test

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): test_main.c ../main.c
	$(CC) $(CFLAGS) $(SANITIZE) -o $@ test_main.c

clean:
	rm -f $(TEST_BIN)
	rm -rf $(TEST_BIN).dSYM

.PHONY: all test clean

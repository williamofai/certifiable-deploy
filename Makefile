# certifiable-deploy Makefile
# Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion
CFLAGS += -Wstrict-prototypes -fno-common -O2 -g
CFLAGS += -I./include

# Source files
AUDIT_SRC = src/audit/sha256.c src/audit/domain_hash.c
ATTEST_SRC = src/attest/merkle.c
TARGET_SRC = src/target/target.c
VERIFY_SRC = src/verify/verify.c

ALL_SRC = $(AUDIT_SRC) $(ATTEST_SRC) $(TARGET_SRC) $(VERIFY_SRC)

# Test executables
TEST_AUDIT = tests/unit/test_audit
TEST_ATTEST = tests/unit/test_attest
TEST_TARGET = tests/unit/test_target
TEST_VERIFY = tests/unit/test_verify

.PHONY: all clean test test-audit test-attest test-target test-verify

all: $(TEST_AUDIT) $(TEST_ATTEST) $(TEST_TARGET) $(TEST_VERIFY)

# Test executables
$(TEST_AUDIT): tests/unit/test_audit.c $(AUDIT_SRC)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_ATTEST): tests/unit/test_attest.c $(AUDIT_SRC) $(ATTEST_SRC)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_TARGET): tests/unit/test_target.c $(TARGET_SRC)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_VERIFY): tests/unit/test_verify.c $(ALL_SRC)
	$(CC) $(CFLAGS) -o $@ $^

# Test targets
test-audit: $(TEST_AUDIT)
	./$(TEST_AUDIT)

test-attest: $(TEST_ATTEST)
	./$(TEST_ATTEST)

test-target: $(TEST_TARGET)
	./$(TEST_TARGET)

test-verify: $(TEST_VERIFY)
	./$(TEST_VERIFY)

test: all
	@echo ""
	@echo "========================================"
	@echo "  certifiable-deploy test suite"
	@echo "========================================"
	@./$(TEST_AUDIT)
	@./$(TEST_ATTEST)
	@./$(TEST_TARGET)
	@./$(TEST_VERIFY)
	@echo "========================================"
	@echo "  All tests passed!"
	@echo "========================================"

clean:
	rm -f $(TEST_AUDIT) $(TEST_ATTEST) $(TEST_TARGET) $(TEST_VERIFY)
	rm -f *.o src/*/*.o tests/unit/*.o

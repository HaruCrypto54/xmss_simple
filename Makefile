CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra -Wpedantic
LDLIBS = -lcrypto

SOURCES = params.c hash.c fips202.c hash_address.c hash_address_2.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c
HEADERS = params.h hash.h fips202.h hash_address.h hash_address_2.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h

SOURCES_simple = $(subst xmss_core.c,xmss_core_simple.c,$(SOURCES))
HEADERS_simple = $(subst xmss_core.c,xmss_core_simple.c,$(HEADERS))

TESTS = test/wots \
		test/oid \
		test/speed \
		test/xmss_determinism \
		test/xmss \
		test/xmss_simple \
		test/xmssmt \
		test/xmssmt_simple \

UI = ui/xmss_keypair \
	 ui/xmss_sign \
	 ui/xmss_open \
	 ui/xmssmt_keypair \
	 ui/xmssmt_sign \
	 ui/xmssmt_open \
	 ui/xmss_keypair_simple \
	 ui/xmss_sign_simple \
	 ui/xmss_open_simple \
	 ui/xmssmt_keypair_simple \
	 ui/xmssmt_sign_simple \
	 ui/xmssmt_open_simple \

all: tests ui

tests: $(TESTS)
ui: $(UI)

test: $(TESTS:=.exec)

.PHONY: clean test

test/%.exec: test/%
	@$<

test/xmss_simple: test/xmss.c $(SOURCES_simple) $(OBJS) $(HEADERS_simple)
	$(CC) -DXMSS_SIGNATURES=1024 $(CFLAGS) -o $@ $(SOURCES_simple) $< $(LDLIBS)

test/xmss: test/xmss.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/xmssmt_simple: test/xmss.c $(SOURCES_simple) $(OBJS) $(HEADERS_simple)
	$(CC) -DXMSSMT -DXMSS_SIGNATURES=1048576 $(CFLAGS) -W -o $@ $(SOURCES_simple) $< $(LDLIBS)

test/xmssmt: test/xmss.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/speed: test/speed.c $(SOURCES_simple) $(OBJS) $(HEADERS_simple)
	$(CC) -DXMSSMT -DXMSS_VARIANT=\"XMSSMT-SHA2_20/2_256\" $(CFLAGS) -o $@ $(SOURCES_simple) $< $(LDLIBS)

test/vectors: test/vectors.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/%: test/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

ui/xmss_%_simple: ui/%.c $(SOURCES_simple) $(OBJS) $(HEADERS_simple)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_simple) $< $(LDLIBS)

ui/xmssmt_%_simple: ui/%.c $(SOURCES_simple) $(OBJS) $(HEADERS_simple)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES_simple) $< $(LDLIBS)

ui/xmss_%: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

ui/xmssmt_%: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

clean:
	-$(RM) $(TESTS)
	-$(RM) test/vectors
	-$(RM) $(UI)
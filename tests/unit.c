/* Rootless unit tests for the pure address helpers. Linked against every
 * object except ndppd.o (which owns main()). */
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "../src/ndppd.h"

/* Globals normally defined in ndppd.c (main's translation unit). */
bool nd_daemonized;
long nd_current_time;

static int failures;
#define CHECK(c) do { if (!(c)) { printf("FAIL - %s (line %d)\n", #c, __LINE__); failures++; } } while (0)

static nd_addr_t A(const char *s)
{
    nd_addr_t a;
    inet_pton(AF_INET6, s, &a);
    return a;
}

int main(void)
{
    nd_addr_t a = A("2001:db8::1"), b = A("2001:db8::2"), c = A("2001:db9::1");
    nd_addr_t ff = A("ff02::1:ff00:1"), un = A("::");

    CHECK(nd_addr_eq(&a, &a));
    CHECK(!nd_addr_eq(&a, &b));
    CHECK(nd_addr_match(&a, &b, 64));
    CHECK(!nd_addr_match(&a, &b, 128));
    CHECK(!nd_addr_match(&a, &c, 48));
    CHECK(nd_addr_is_multicast(&ff));
    CHECK(!nd_addr_is_multicast(&a));
    CHECK(nd_addr_is_unspecified(&un));
    CHECK(!nd_addr_is_unspecified(&a));
    CHECK(nd_addr_hash(&a) != nd_addr_hash(&b));
    CHECK(strcmp(nd_ntoa(&a), "2001:db8::1") == 0);

    nd_addr_t r, pfx = A("fd00:1::"), host = A("::5");
    nd_addr_combine(&pfx, &host, 64, &r);
    CHECK(nd_addr_eq(&r, &(nd_addr_t){ .u8 = { 0xfd, 0, 0, 1, [15] = 5 } }));

    nd_lladdr_t ll = { 0x02, 0, 0, 0xaa, 0xbb, 0xcc };
    CHECK(strcmp(nd_ll_ntoa(&ll), "2:0:0:aa:bb:cc") == 0);

    if (!failures)
        printf("ok   - unit tests\n");
    return failures ? 1 : 0;
}

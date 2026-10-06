// A PE and its PDB whose contents are known before any reader runs: every
// function name, the one static, the struct's offsets and the enum's values.
#include <stdint.h>
#include <stdio.h>

struct Connection {
    int32_t retries;          // +0
    float timeout;            // +4
    struct Connection *next;  // +8
    char host[16];            // +16, sizeof == 32
};

enum State { STATE_IDLE = 0, STATE_OPEN = 7, STATE_CLOSED = 42 };

__attribute__((noinline)) int record_failure(struct Connection *c, int count) {
    c->retries -= count;
    return c->retries;
}

__attribute__((noinline)) float doubled_timeout(const struct Connection *c) { return c->timeout * 2.0f; }

static __attribute__((noinline)) int helper_static(int x) { return x * 3 + 1; }

__attribute__((noinline)) enum State state_of(const struct Connection *c) {
    return c->retries <= 0 ? STATE_CLOSED : (c->timeout > 1.0f ? STATE_OPEN : STATE_IDLE);
}

int main(int argc, char **argv) {
    (void)argv;
    struct Connection conn = { 100, 1.5f, 0, "localhost" };
    record_failure(&conn, argc);
    printf("%d %f %d %d\n", conn.retries, doubled_timeout(&conn), helper_static(argc), (int)state_of(&conn));
    return 0;
}

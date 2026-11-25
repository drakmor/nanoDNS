#!/usr/bin/env python3
"""Exercise the production forwarding loop without a console SDK or public DNS.

Run: python3 tests/upstream-regression.py [path/to/main.c]
Only the forwarding function is compiled, with scripted socket operations. This
keeps the regression independent of the console startup/privilege code and the
separate proposal to add a full host platform (PR #24).
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile


source = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "main.c"
text = source.read_text()
start = text.index("static int\nforward_query_to_upstream(")
opening = text.index("{", start)
depth = 1
end = opening + 1
while depth:
    depth += (text[end] == "{") - (text[end] == "}")
    end += 1
forwarding = text[start:end]

harness = r'''
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef struct { struct in_addr addr; char text[INET_ADDRSTRLEN]; } upstream_t;
typedef struct { int timeout_ms; size_t upstream_count; upstream_t upstreams[2]; } app_config_t;
enum answer { VALID, ECHO_QUERY, WRONG_ID, SHORT_PACKET };
static app_config_t cfg;
static enum answer replies[2];
static int opened, closed, sends, owner[32];
static unsigned char query[12] = {0x12,0x34,1,0,0,1,0,0,0,0,0,0};

static uint16_t read_u16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static int64_t now_ms(void) { return 100; }
#define log_printf(...) ((void)0)
static int open_upstream_socket(const upstream_t *upstream) {
  int fd = ++opened;
  assert(fd < 32);
  owner[fd] = (int)(upstream - cfg.upstreams);
  return fd;
}
static void close_upstream_socket(int *fd) {
  assert(*fd > 0);
  ++closed;
  *fd = -1;
}
static int drain_upstream_socket(int fd) { (void)fd; return 0; }
static ssize_t fake_send(int fd, const void *buf, size_t len, int flags) {
  (void)fd; (void)flags;
  assert(len == sizeof(query) && memcmp(buf, query, len) == 0);
  ++sends;
  return (ssize_t)len;
}
static int fake_poll(struct pollfd *p, nfds_t count, int timeout) {
  assert(count == 1 && timeout > 0);
  p->revents = POLLIN;
  return 1;
}
static ssize_t fake_recv(int fd, void *buf, size_t len, int flags) {
  (void)flags;
  assert(len >= sizeof(query));
  unsigned char *p = buf;
  memcpy(p, query, sizeof(query));
  switch(replies[owner[fd]]) {
  case SHORT_PACKET: return 5;
  case ECHO_QUERY: return sizeof(query);
  case WRONG_ID: p[0] ^= 1; /* fall through */
  case VALID: p[2] |= 0x80; return sizeof(query);
  }
  assert(0); return -1;
}
#define send fake_send
#define poll fake_poll
#define recv fake_recv
''' + forwarding + r'''

static void reset(enum answer first, enum answer second) {
  memset(&cfg, 0, sizeof(cfg));
  cfg.timeout_ms = 1500;
  cfg.upstream_count = 2;
  strcpy(cfg.upstreams[0].text, "192.0.2.1");
  strcpy(cfg.upstreams[1].text, "192.0.2.2");
  replies[0] = first; replies[1] = second;
  opened = closed = sends = 0;
}
static int forward(int *fds, unsigned char *response, char *via) {
  size_t len = 0;
  int rc = forward_query_to_upstream(&cfg, query, sizeof(query), 0x1234,
                                    fds, response, 512, &len, via, INET_ADDRSTRLEN);
  if(rc == 0) assert(len == sizeof(query) && (response[2] & 0x80));
  return rc;
}
int main(void) {
  unsigned char response[512];
  char via[INET_ADDRSTRLEN];
  int fds[2] = {-1,-1};

  reset(ECHO_QUERY, VALID);
  assert(forward(fds, response, via) == 0);
  assert(strcmp(via, "192.0.2.2") == 0 && sends == 2 && closed == 2);

  reset(ECHO_QUERY, ECHO_QUERY);
  assert(forward(fds, response, via) == -1);
  assert(sends == 2 && closed == 2 && fds[0] == -1 && fds[1] == -1);

  reset(VALID, VALID);
  assert(forward(fds, response, via) == 0);
  assert(strcmp(via, "192.0.2.1") == 0 && closed == 1 && fds[0] == -1);
  assert(forward(fds, response, via) == 0);
  assert(opened == 2 && closed == 2); /* fresh socket for the next query */

  reset(WRONG_ID, VALID);
  assert(forward(fds, response, via) == 0);
  assert(strcmp(via, "192.0.2.2") == 0 && closed == 2);

  reset(SHORT_PACKET, VALID);
  assert(forward(fds, response, via) == 0);
  assert(strcmp(via, "192.0.2.2") == 0 && closed == 2);
  puts("PASS: query rejection, failover, valid replies, fresh sockets, wrong IDs, short packets");
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="nanodns-upstream-") as directory:
    root = Path(directory)
    (root / "test.c").write_text(harness)
    executable = root / "test"
    subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-g", str(root / "test.c"), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)

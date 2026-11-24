/*
 * Host-side unit tests for nanoDNS.
 *
 * main.c is compiled directly into this file (with PLATFORM_HOST) so the
 * static helpers can be tested without the PS4/PS5 SDKs. Its main() is
 * renamed so this file can provide its own.
 */
#define main nanodns_main
#include "../main.c"
#undef main

/* Platform stubs: never called by the tests, but needed to link. */
int sceNetInit(void) { return 0; }
int sceNetPoolCreate(const char *name, int size, int flags) {
  (void)name;
  (void)size;
  (void)flags;
  return 1;
}
int sceNetPoolDestroy(int memid) {
  (void)memid;
  return 0;
}
int sceNetTerm(void) { return 0; }
int sceKernelSendNotificationRequest(int a, void *b, size_t c, int d) {
  (void)a;
  (void)b;
  (void)c;
  (void)d;
  return 0;
}
int kernel_set_ucred_authid(pid_t pid, uint64_t authid) {
  (void)pid;
  (void)authid;
  return 0;
}

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond)                                                           \
  do {                                                                        \
    ++g_checks;                                                               \
    if(!(cond)) {                                                             \
      ++g_failures;                                                           \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,       \
              #cond);                                                         \
    }                                                                         \
  } while(0)

#define CHECK_STR(actual, expected)                                           \
  do {                                                                        \
    const char *a_ = (actual);                                                \
    const char *e_ = (expected);                                              \
    ++g_checks;                                                               \
    if(strcmp(a_, e_) != 0) {                                                 \
      ++g_failures;                                                           \
      fprintf(stderr, "%s:%d: expected \"%s\", got \"%s\"\n", __FILE__,       \
              __LINE__, e_, a_);                                              \
    }                                                                         \
  } while(0)

/* ---- helpers ---------------------------------------------------------- */

/* Encode "a.b.c" as DNS labels at buf; returns bytes written. */
static size_t
encode_name(uint8_t *buf, const char *name) {
  size_t out = 0;

  while(*name != '\0') {
    const char *dot = strchr(name, '.');
    size_t len = dot ? (size_t)(dot - name) : strlen(name);

    buf[out++] = (uint8_t)len;
    memcpy(&buf[out], name, len);
    out += len;
    name += len;
    if(*name == '.') {
      ++name;
    }
  }

  buf[out++] = 0;
  return out;
}

/* Build a standard query (RD set) for name/qtype; returns packet length. */
static size_t
build_query(uint8_t *buf, uint16_t id, const char *name, uint16_t qtype) {
  size_t len;

  memset(buf, 0, 12);
  write_u16(&buf[0], id);
  write_u16(&buf[2], 0x0100);
  write_u16(&buf[4], 1);
  len = 12 + encode_name(&buf[12], name);
  write_u16(&buf[len], qtype);
  write_u16(&buf[len + 2], 1);
  return len + 4;
}

static int
write_temp_config(char *path, size_t path_len, const char *contents) {
  int fd;
  FILE *fp;

  snprintf(path, path_len, "/tmp/nanodns-test-XXXXXX");
  fd = mkstemp(path);
  if(fd < 0) {
    return -1;
  }

  fp = fdopen(fd, "w");
  if(fp == NULL) {
    close(fd);
    return -1;
  }

  fputs(contents, fp);
  fclose(fp);
  return 0;
}

/* Load contents as a config file into cfg; returns load_config's result. */
static int
load_config_text(const char *contents, app_config_t *cfg) {
  char path[64];
  int rc;

  if(write_temp_config(path, sizeof(path), contents) != 0) {
    return -100;
  }

  rc = load_config(path, cfg);
  unlink(path);
  return rc;
}

static bool
has_warning_containing(const app_config_t *cfg, const char *needle) {
  for(size_t i = 0; i < cfg->warning_count; ++i) {
    if(strstr(cfg->warnings[i].text, needle) != NULL) {
      return true;
    }
  }

  return false;
}

/* ---- domain_mask_match ------------------------------------------------ */

static void
test_domain_mask_match(void) {
  static const struct {
    const char *mask;
    const char *domain;
    int expected;
  } cases[] = {
      {"example.com", "example.com", 1},
      {"example.com", "www.example.com", 0},
      {"example.com", "example.co", 0},
      {"*.example.com", "www.example.com", 1},
      {"*.example.com", "a.b.example.com", 1},
      {"*.example.com", "example.com", 0},
      {"*.example.com", "badexample.com", 0},
      {"*.playstation.com.*", "api.playstation.com.lan", 1},
      {"*.playstation.com.*", "api.playstation.com", 0},
      {"stun.*.playstation.net", "stun.eu.playstation.net", 1},
      {"stun.*.playstation.net", "stun.playstation.net", 0},
      {"api??.test.local", "api01.test.local", 1},
      {"api??.test.local", "api1.test.local", 0},
      {"api??.test.local", "api001.test.local", 0},
      {"[ab]*.lab", "alpha.lab", 1},
      {"[ab]*.lab", "beta.lab", 1},
      {"[ab]*.lab", "gamma.lab", 0},
      {"host[0-9].lan", "host7.lan", 1},
      {"host[0-9].lan", "hostx.lan", 0},
      {"host[!0-9].lan", "hostx.lan", 1},
      {"host[!0-9].lan", "host7.lan", 0},
      {"host[^0-9].lan", "hostx.lan", 1},
      {"*", "anything.at.all", 1},
      {"**.example.com", "www.example.com", 1},
      {"a\\*b", "a*b", 1},
      {"a\\*b", "axb", 0},
      /* unterminated class is treated as a literal '[' */
      {"[abc", "[abc", 1},
      {"[abc", "a", 0},
      {"", "", 1},
      {"", "x", 0},
  };

  for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    int got = domain_mask_match(cases[i].mask, cases[i].domain);

    ++g_checks;
    if(got != cases[i].expected) {
      ++g_failures;
      fprintf(stderr, "domain_mask_match(\"%s\", \"%s\") = %d, expected %d\n",
              cases[i].mask, cases[i].domain, got, cases[i].expected);
    }
  }
}

/* ---- normalize_domain ------------------------------------------------- */

static void
test_normalize_domain(void) {
  char out[MAX_DOMAIN_LEN];
  char small[4];

  normalize_domain("WWW.Example.COM.", out, sizeof(out));
  CHECK_STR(out, "www.example.com");

  normalize_domain("example.com...", out, sizeof(out));
  CHECK_STR(out, "example.com");

  normalize_domain(".", out, sizeof(out));
  CHECK_STR(out, "");

  normalize_domain("ABCDEF", small, sizeof(small));
  CHECK_STR(small, "abc");

  /* in-place use, as config_add_rule() does */
  snprintf(out, sizeof(out), "Mixed.Case.");
  normalize_domain(out, out, sizeof(out));
  CHECK_STR(out, "mixed.case");
}

/* ---- load_config ------------------------------------------------------ */

static void
test_config_defaults_when_missing(void) {
  app_config_t cfg;

  CHECK(load_config("/nonexistent/nanodns-test.ini", &cfg) == -1);
  CHECK(cfg.upstream_count == 3);
  CHECK(cfg.timeout_ms == DEFAULT_TIMEOUT_MS);
  CHECK_STR(cfg.bind_text, "127.0.0.1");
  CHECK(cfg.bind6_enabled);
  CHECK_STR(cfg.bind6_text, "::1");
}

static void
test_config_full(void) {
  app_config_t cfg;

  CHECK(load_config_text("[general]\n"
                         "log=/tmp/x.log\n"
                         "debug=1\n"
                         "quiet=1\n"
                         "bind=0.0.0.0\n"
                         "bind6=off\n"
                         "\n"
                         "[upstream]\n"
                         "server=9.9.9.9   # inline comment\n"
                         "dns=1.0.0.1 ; other comment style\n"
                         "timeout_ms=900\n"
                         "\n"
                         "[overrides]\n"
                         "*.Example.COM.=10.0.0.1\n"
                         "exact.host=10.0.0.2\n"
                         "\n"
                         "[exceptions]\n"
                         "Keep.Example.com\n"
                         "*.allowed.example.com=ignored\n",
                         &cfg) == 0);

  CHECK_STR(cfg.log_path, "/tmp/x.log");
  CHECK(cfg.debug_enabled == 1);
  CHECK(cfg.quiet_enabled == 1);
  CHECK_STR(cfg.bind_text, "0.0.0.0");
  CHECK(!cfg.bind6_enabled);

  /* configured servers replace the built-in list */
  CHECK(cfg.upstream_count == 2);
  CHECK_STR(cfg.upstreams[0].text, "9.9.9.9");
  CHECK_STR(cfg.upstreams[1].text, "1.0.0.1");
  CHECK(cfg.timeout_ms == 900);

  CHECK(cfg.rule_count == 2);
  CHECK_STR(cfg.rules[0].mask, "*.example.com");
  CHECK_STR(cfg.rules[0].text, "10.0.0.1");
  CHECK_STR(cfg.rules[1].mask, "exact.host");

  CHECK(cfg.exception_count == 2);
  CHECK_STR(cfg.exceptions[0].mask, "keep.example.com");
  CHECK_STR(cfg.exceptions[1].mask, "*.allowed.example.com");

  CHECK(cfg.warning_count == 0);
}

static void
test_config_without_sections_and_overrides(void) {
  app_config_t cfg;

  /* general keys are accepted before any section header */
  CHECK(load_config_text("debug=1\nbind6=::\n", &cfg) == 0);
  CHECK(cfg.debug_enabled == 1);
  CHECK(cfg.bind6_enabled);
  CHECK_STR(cfg.bind6_text, "::");

  /* an existing config without [overrides] means no overrides */
  CHECK(cfg.rule_count == 0);
  CHECK(cfg.exception_count == 0);
  /* and without [upstream] keeps the built-in servers */
  CHECK(cfg.upstream_count == 3);
}

static void
test_config_invalid_values(void) {
  app_config_t cfg;

  CHECK(load_config_text("[general]\n"
                         "debug=yes\n"
                         "bind=not-an-ip\n"
                         "bind6=::zz\n"
                         "[upstream]\n"
                         "server=1.2.3\n"
                         "timeout_ms=-5\n"
                         "[overrides]\n"
                         "bad.example=300.1.1.1\n",
                         &cfg) == 0);

  CHECK(cfg.debug_enabled == 0);
  CHECK_STR(cfg.bind_text, "127.0.0.1");
  CHECK_STR(cfg.bind6_text, "::1");
  CHECK(cfg.timeout_ms == DEFAULT_TIMEOUT_MS);
  CHECK(cfg.rule_count == 0);
  /* all configured servers invalid: fall back to built-in servers */
  CHECK(cfg.upstream_count == 3);

  CHECK(has_warning_containing(&cfg, "invalid debug value 'yes'"));
  CHECK(has_warning_containing(&cfg, "invalid bind address 'not-an-ip'"));
  CHECK(has_warning_containing(&cfg, "invalid bind6 address '::zz'"));
  CHECK(has_warning_containing(&cfg, "invalid upstream server '1.2.3'"));
  CHECK(has_warning_containing(&cfg, "invalid timeout_ms '-5'"));
  CHECK(has_warning_containing(&cfg, "invalid override IPv4 '300.1.1.1'"));
}

static void
test_config_limits(void) {
  app_config_t cfg;
  char text[16384];
  size_t len;

  len = (size_t)snprintf(text, sizeof(text), "[upstream]\n");
  for(int i = 0; i < MAX_UPSTREAMS + 2; ++i) {
    len += (size_t)snprintf(&text[len], sizeof(text) - len,
                            "server=10.0.0.%d\n", i + 1);
  }
  len += (size_t)snprintf(&text[len], sizeof(text) - len, "[overrides]\n");
  for(int i = 0; i < MAX_RULES + 1; ++i) {
    len += (size_t)snprintf(&text[len], sizeof(text) - len,
                            "h%d.test=10.1.0.1\n", i);
  }
  CHECK(len < sizeof(text));

  CHECK(load_config_text(text, &cfg) == 0);
  CHECK(cfg.upstream_count == MAX_UPSTREAMS);
  CHECK(cfg.rule_count == MAX_RULES);
  CHECK(has_warning_containing(&cfg, "too many upstream servers"));
  CHECK(has_warning_containing(&cfg, "too many override rules"));
}

/* ---- DNS parsing ------------------------------------------------------ */

static void
test_dns_parse_question(void) {
  uint8_t pkt[512];
  dns_question_t q;
  size_t len;

  len = build_query(pkt, 0x1234, "WWW.Example.Com", 28);
  CHECK(dns_parse_question(pkt, len, &q) == 0);
  CHECK(q.id == 0x1234);
  CHECK(q.qdcount == 1);
  CHECK(q.qtype == 28);
  CHECK(q.qclass == 1);
  CHECK(q.question_end == len);
  CHECK_STR(q.qname, "www.example.com");

  /* root name */
  len = build_query(pkt, 1, "", 2);
  CHECK(dns_parse_question(pkt, len, &q) == 0);
  CHECK_STR(q.qname, "");

  /* header only / truncated question */
  len = build_query(pkt, 1, "example.com", 1);
  CHECK(dns_parse_question(pkt, 11, &q) != 0);
  CHECK(dns_parse_question(pkt, 12, &q) != 0);
  CHECK(dns_parse_question(pkt, len - 1, &q) != 0);
  CHECK(dns_parse_question(pkt, 16, &q) != 0);

  /* qdcount == 0 */
  len = build_query(pkt, 1, "example.com", 1);
  write_u16(&pkt[4], 0);
  CHECK(dns_parse_question(pkt, len, &q) != 0);
}

static void
test_dns_expand_name_rejects_bad_input(void) {
  uint8_t pkt[600];
  char name[MAX_DOMAIN_LEN];
  size_t off;

  /* compression pointer pointing at itself */
  memset(pkt, 0, sizeof(pkt));
  pkt[12] = 0xc0;
  pkt[13] = 12;
  off = 12;
  CHECK(dns_expand_name(pkt, 14, &off, name, sizeof(name)) != 0);

  /* pointer past the end of the packet */
  pkt[13] = 200;
  off = 12;
  CHECK(dns_expand_name(pkt, 14, &off, name, sizeof(name)) != 0);

  /* reserved label type bits (0x40 / 0x80) */
  pkt[12] = 0x41;
  off = 12;
  CHECK(dns_expand_name(pkt, 80, &off, name, sizeof(name)) != 0);

  /* label running past the end of the packet */
  pkt[12] = 10;
  memcpy(&pkt[13], "abc", 3);
  off = 12;
  CHECK(dns_expand_name(pkt, 16, &off, name, sizeof(name)) != 0);

  /* name longer than the output buffer: 5 labels of 63 bytes */
  off = 12;
  for(int i = 0; i < 5; ++i) {
    pkt[off++] = 63;
    memset(&pkt[off], 'a', 63);
    off += 63;
  }
  pkt[off++] = 0;
  {
    size_t total = off;

    off = 12;
    CHECK(dns_expand_name(pkt, total, &off, name, sizeof(name)) != 0);
  }

  /* valid compression: name at 12, pointer to it at the end */
  off = 12 + encode_name(&pkt[12], "example.com");
  pkt[off] = 0xc0;
  pkt[off + 1] = 12;
  {
    size_t ptr_at = off;

    CHECK(dns_expand_name(pkt, ptr_at + 2, &off, name, sizeof(name)) == 0);
    CHECK_STR(name, "example.com");
    CHECK(off == ptr_at + 2);
  }
}

/* ---- response building ------------------------------------------------ */

static void
test_build_override_response(void) {
  uint8_t req[512];
  uint8_t resp[MAX_DNS_PACKET];
  dns_question_t q;
  struct in_addr addr;
  size_t req_len;
  size_t resp_len = 0;
  dns_question_t rq;

  req_len = build_query(req, 0xbeef, "blocked.example.com", 1);
  CHECK(dns_parse_question(req, req_len, &q) == 0);
  CHECK(inet_pton(AF_INET, "10.20.30.40", &addr) == 1);

  CHECK(build_override_response(req, &q, &addr, resp, sizeof(resp),
                                &resp_len) == 0);
  CHECK(resp_len == req_len + 16);
  CHECK(read_u16(&resp[0]) == 0xbeef);
  /* QR | RD copied | RA, NOERROR */
  CHECK(read_u16(&resp[2]) == 0x8180);
  CHECK(read_u16(&resp[4]) == 1);
  CHECK(read_u16(&resp[6]) == 1);
  CHECK(read_u16(&resp[8]) == 0);
  CHECK(read_u16(&resp[10]) == 0);

  /* answer: pointer to qname, A, IN, TTL, 4 bytes of address */
  CHECK(read_u16(&resp[req_len]) == 0xc00c);
  CHECK(read_u16(&resp[req_len + 2]) == 1);
  CHECK(read_u16(&resp[req_len + 4]) == 1);
  CHECK(read_u32(&resp[req_len + 6]) == OVERRIDE_TTL);
  CHECK(read_u16(&resp[req_len + 10]) == 4);
  CHECK(memcmp(&resp[req_len + 12], &addr.s_addr, 4) == 0);

  /* the response parses back to the same question */
  CHECK(dns_parse_question(resp, resp_len, &rq) == 0);
  CHECK_STR(rq.qname, "blocked.example.com");

  /* buffer too small */
  CHECK(build_override_response(req, &q, &addr, resp, req_len + 15,
                                &resp_len) != 0);
}

static void
test_build_error_and_nodata_response(void) {
  uint8_t req[512];
  uint8_t resp[MAX_DNS_PACKET];
  dns_question_t q;
  size_t req_len;
  size_t resp_len = 0;

  req_len = build_query(req, 0x0042, "example.com", 28);
  /* pretend the client also sent an additional record (e.g. EDNS) */
  write_u16(&req[10], 1);
  CHECK(dns_parse_question(req, req_len, &q) == 0);

  CHECK(build_error_response(req, req_len, &q, 2, resp, sizeof(resp),
                             &resp_len) == 0);
  CHECK(resp_len == req_len);
  CHECK(read_u16(&resp[0]) == 0x0042);
  CHECK(read_u16(&resp[2]) == 0x8182);
  CHECK(read_u16(&resp[4]) == 1);
  CHECK(read_u16(&resp[6]) == 0);
  CHECK(read_u16(&resp[10]) == 0);

  CHECK(build_nodata_response(req, req_len, &q, resp, sizeof(resp),
                              &resp_len) == 0);
  CHECK((read_u16(&resp[2]) & 0x000f) == 0);
  CHECK(read_u16(&resp[6]) == 0);

  /* RD not set in the query: not set in the response either */
  write_u16(&req[2], 0x0000);
  CHECK(dns_parse_question(req, req_len, &q) == 0);
  CHECK(build_error_response(req, req_len, &q, 3, resp, sizeof(resp),
                             &resp_len) == 0);
  CHECK(read_u16(&resp[2]) == 0x8083);
}

/* ---- override / exception lookup -------------------------------------- */

static void
test_rule_and_exception_lookup(void) {
  app_config_t cfg;
  const override_rule_t *rule;

  config_set_defaults(&cfg);
  CHECK(config_apply_builtin_overrides(&cfg) == 0);
  config_apply_builtin_exceptions(&cfg);

  rule = find_matching_rule(&cfg, "api.playstation.com");
  CHECK(rule != NULL);
  CHECK(rule != NULL && strcmp(rule->mask, "*.playstation.com") == 0);
  CHECK(find_matching_rule(&cfg, "playstation.net") != NULL);
  CHECK(find_matching_rule(&cfg, "example.com") == NULL);

  CHECK(has_matching_exception(&cfg, "feature.api.playstation.com"));
  CHECK(has_matching_exception(&cfg, "eu.stun.playstation.net"));
  CHECK(has_matching_exception(&cfg, "stun.us.playstation.net"));
  CHECK(!has_matching_exception(&cfg, "api.playstation.com"));
}

int
main(void) {
  test_domain_mask_match();
  test_normalize_domain();
  test_config_defaults_when_missing();
  test_config_full();
  test_config_without_sections_and_overrides();
  test_config_invalid_values();
  test_config_limits();
  test_dns_parse_question();
  test_dns_expand_name_rejects_bad_input();
  test_build_override_response();
  test_build_error_and_nodata_response();
  test_rule_and_exception_lookup();

  if(g_failures != 0) {
    fprintf(stderr, "%d of %d checks failed\n", g_failures, g_checks);
    return 1;
  }

  printf("all %d checks passed\n", g_checks);
  return 0;
}

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(PLATFORM_PS4)
#include <ps4/kernel.h>
#include <ps4/klog.h>
#define PAYLOAD_EXEC_NAME "nanodns-ps4.elf"
#elif defined(PLATFORM_PS5)
#include <ps5/kernel.h>
#include <ps5/klog.h>
#define PAYLOAD_EXEC_NAME "nanodns.elf"
#else
#error "Define PLATFORM_PS4 or PLATFORM_PS5"
#endif

#define APP_NAME "NanoDNS"
#define APP_VERSION "0.2"
#define APP_COPYRIGHT "(c) Drakmor"
#define DATA_DIR "/data/nanodns"
#define CONFIG_PATH DATA_DIR "/nanodns.ini"
#define DEFAULT_LOG_PATH DATA_DIR "/nanodns.log"
#define DNS_PORT 53
#define MAX_DNS_PACKET 4096
#define MAX_UPSTREAMS 8
#define MAX_RULES 128
#define MAX_EXCEPTIONS 128
#define MAX_CONFIG_WARNINGS 128
#define MAX_CONFIG_WARNING_LEN 256
#define MAX_DOMAIN_LEN 256
#define MAX_LOG_PATH 256
#define DEFAULT_TIMEOUT_MS 1500
#define OVERRIDE_TTL 60
#define PRIVILEGED_AUTHID 0x4801000000000013L
#define KI_PID_OFFSET 72
#define KI_TDNAME_OFFSET 447

int sceNetInit(void);
int sceNetPoolCreate(const char *name, int size, int flags);
int sceNetPoolDestroy(int memid);
int sceNetTerm(void);
int sceKernelSendNotificationRequest(int, void *, size_t, int);

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;

typedef struct {
  struct in_addr addr;
  char text[INET_ADDRSTRLEN];
} upstream_t;

typedef struct {
  char mask[MAX_DOMAIN_LEN];
  struct in_addr addr;
  char text[INET_ADDRSTRLEN];
} override_rule_t;

typedef struct {
  char mask[MAX_DOMAIN_LEN];
} exception_rule_t;

typedef struct {
  char text[MAX_CONFIG_WARNING_LEN];
} config_warning_t;

typedef struct {
  upstream_t upstreams[MAX_UPSTREAMS];
  size_t upstream_count;
  override_rule_t rules[MAX_RULES];
  size_t rule_count;
  exception_rule_t exceptions[MAX_EXCEPTIONS];
  size_t exception_count;
  int timeout_ms;
  int debug_enabled;
  struct in_addr bind_addr;
  char bind_text[INET_ADDRSTRLEN];
  char log_path[MAX_LOG_PATH];
  config_warning_t warnings[MAX_CONFIG_WARNINGS];
  size_t warning_count;
} app_config_t;

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
  size_t qname_offset;
  size_t question_end;
  char qname[MAX_DOMAIN_LEN];
  uint16_t qtype;
  uint16_t qclass;
} dns_question_t;

static volatile sig_atomic_t g_running = 1;
static int g_libnet_mem_id = -1;
static int g_debug_enabled = 1;
static FILE *g_log_file = NULL;

static const char *k_default_config =
    "# " APP_NAME " configuration\n"
    "#\n"
    "# [general]\n"
    "# log=<path>\n"
    "# debug=0|1\n"
    "# bind=<IPv4>\n"
    "# Use 0.0.0.0 to listen on all IPv4 interfaces\n"
    "#\n"
    "# [upstream]\n"
    "# server=<IPv4>\n"
    "# Servers are tried in order until one replies\n"
    "# timeout_ms=<integer-total-budget>\n"
    "#\n"
    "# [overrides]\n"
    "# <dns-mask>=<IPv4>\n"
    "# Supports shell-style masks: *.example.com, api??.test.local, [ab]*.lab\n"
    "#\n"
    "# [exceptions]\n"
    "# One hostname or mask per line; these bypass local overrides\n"
    "\n"
    "[general]\n"
    "log=" DEFAULT_LOG_PATH "\n"
    "debug=0\n"
    "bind=127.0.0.1\n"
    "\n"
    "[upstream]\n"
    "server=1.1.1.1\n"
    "server=8.8.8.8\n"
    "server=77.77.88.88\n"
    "timeout_ms=1500\n"
    "\n"
    "[overrides]\n"
    "*.playstation.com=0.0.0.0\n"
    "*.playstation.com.*=0.0.0.0\n"
    "playstation.com=0.0.0.0\n"
    "*.playstation.net=0.0.0.0\n"
    "*.playstation.net.*=0.0.0.0\n"
    "*.psndl.net=0.0.0.0\n"
    "playstation.net=0.0.0.0\n"
    "psndl.net=0.0.0.0\n"
    "# *.example.com=192.168.0.10\n"
    "# exact.host.local=10.0.0.42\n"
    "\n"
    "[exceptions]\n"
    "feature.api.playstation.com\n"
    "*.stun.playstation.net\n"
    "stun.*.playstation.net\n"
    "ena.net.playstation.net\n"
    "post.net.playstation.net\n"
    "gst.prod.dl.playstation.net\n"
    "# auth.api.playstation.net\n"
    "# *.allowed.playstation.net\n";

static void
log_emit_direct(const char *buf, int to_debug) {
  if(g_log_file != NULL) {
    fputs(buf, g_log_file);
    fflush(g_log_file);
  }

  if(to_debug) {
    fputs(buf, stdout);
    fflush(stdout);
    klog_printf("%s", buf);
  }
}

static int
logger_init(const app_config_t *cfg) {
  char buf[512];

  if(g_log_file != NULL) {
    fclose(g_log_file);
    g_log_file = NULL;
  }

  g_debug_enabled = cfg->debug_enabled ? 1 : 0;
  g_log_file = fopen(cfg->log_path, "w");
  if(g_log_file == NULL) {
    if(!g_debug_enabled) {
      g_debug_enabled = 1;
    }

    snprintf(buf, sizeof(buf), "[nanodns] failed to open log file %s: %s\n",
             cfg->log_path, strerror(errno));
    log_emit_direct(buf, g_debug_enabled);
    return -1;
  }

  setvbuf(g_log_file, NULL, _IOLBF, 0);
  return 0;
}

static void
logger_fini(void) {
  if(g_log_file != NULL) {
    fclose(g_log_file);
    g_log_file = NULL;
  }
}

static void
log_printf(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  int written;

  va_start(ap, fmt);
  written = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if(written < 0) {
    return;
  }

  log_emit_direct(buf, g_debug_enabled);
}

static void
log_errno(const char *what) {
  log_printf("[nanodns] %s: %s\n", what, strerror(errno));
}

static const char *
dns_type_to_string(uint16_t qtype) {
  switch(qtype) {
  case 1:
    return "A";
  case 2:
    return "NS";
  case 5:
    return "CNAME";
  case 6:
    return "SOA";
  case 12:
    return "PTR";
  case 15:
    return "MX";
  case 16:
    return "TXT";
  case 28:
    return "AAAA";
  case 33:
    return "SRV";
  case 41:
    return "OPT";
  case 255:
    return "ANY";
  default:
    return "OTHER";
  }
}

static const char *
dns_rcode_to_string(uint16_t rcode) {
  switch(rcode) {
  case 0:
    return "NOERROR";
  case 1:
    return "FORMERR";
  case 2:
    return "SERVFAIL";
  case 3:
    return "NXDOMAIN";
  case 4:
    return "NOTIMP";
  case 5:
    return "REFUSED";
  default:
    return "OTHER";
  }
}

static uint16_t
read_u16(const uint8_t *ptr) {
  return (uint16_t)(((uint16_t)ptr[0] << 8) | ptr[1]);
}

static uint32_t
read_u32(const uint8_t *ptr) {
  return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) |
         ((uint32_t)ptr[2] << 8) | ptr[3];
}

static void
write_u16(uint8_t *ptr, uint16_t value) {
  ptr[0] = (uint8_t)((value >> 8) & 0xff);
  ptr[1] = (uint8_t)(value & 0xff);
}

static void
write_u32(uint8_t *ptr, uint32_t value) {
  ptr[0] = (uint8_t)((value >> 24) & 0xff);
  ptr[1] = (uint8_t)((value >> 16) & 0xff);
  ptr[2] = (uint8_t)((value >> 8) & 0xff);
  ptr[3] = (uint8_t)(value & 0xff);
}

static char *
ltrim(char *s) {
  while(*s && isspace((unsigned char)*s)) {
    ++s;
  }

  return s;
}

static void
rtrim(char *s) {
  size_t len = strlen(s);

  while(len > 0 && isspace((unsigned char)s[len - 1])) {
    s[--len] = '\0';
  }
}

static char *
trim(char *s) {
  s = ltrim(s);
  rtrim(s);
  return s;
}

static void
strip_inline_comment(char *s) {
  char *hash = strchr(s, '#');
  char *semi = strchr(s, ';');
  char *cut = NULL;

  if(hash && semi) {
    cut = hash < semi ? hash : semi;
  } else if(hash) {
    cut = hash;
  } else if(semi) {
    cut = semi;
  }

  if(cut) {
    *cut = '\0';
    rtrim(s);
  }
}

static void
normalize_domain(const char *input, char *output, size_t output_size) {
  size_t out = 0;

  if(output_size == 0) {
    return;
  }

  for(; *input != '\0' && out + 1 < output_size; ++input) {
    output[out++] = (char)tolower((unsigned char)*input);
  }

  while(out > 0 && output[out - 1] == '.') {
    --out;
  }

  output[out] = '\0';
}

static int
parse_int_strict(const char *text, int *value) {
  char *end = NULL;
  long parsed;

  errno = 0;
  parsed = strtol(text, &end, 10);
  if(errno != 0 || end == text || *end != '\0' || parsed < INT_MIN ||
     parsed > INT_MAX) {
    return -1;
  }

  *value = (int)parsed;
  return 0;
}

static void
config_add_warning(app_config_t *cfg, const char *fmt, ...) {
  va_list ap;

  if(cfg->warning_count >= MAX_CONFIG_WARNINGS) {
    return;
  }

  va_start(ap, fmt);
  vsnprintf(cfg->warnings[cfg->warning_count].text, MAX_CONFIG_WARNING_LEN, fmt,
            ap);
  va_end(ap);
  ++cfg->warning_count;
}

static int
config_set_bind_address(app_config_t *cfg, const char *ip) {
  if(inet_pton(AF_INET, ip, &cfg->bind_addr) != 1) {
    return -1;
  }

  snprintf(cfg->bind_text, sizeof(cfg->bind_text), "%s", ip);
  return 0;
}

static void
config_set_defaults(app_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
  cfg->debug_enabled = 0;
  (void)config_set_bind_address(cfg, "127.0.0.1");
  snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", DEFAULT_LOG_PATH);
}

static int
config_add_upstream(app_config_t *cfg, const char *ip) {
  upstream_t *upstream;

  if(cfg->upstream_count >= MAX_UPSTREAMS) {
    return -1;
  }

  upstream = &cfg->upstreams[cfg->upstream_count];
  if(inet_pton(AF_INET, ip, &upstream->addr) != 1) {
    return -1;
  }

  snprintf(upstream->text, sizeof(upstream->text), "%s", ip);
  ++cfg->upstream_count;
  return 0;
}

static int
config_add_rule(app_config_t *cfg, const char *mask, const char *ip) {
  override_rule_t *rule;

  if(cfg->rule_count >= MAX_RULES) {
    return -1;
  }

  rule = &cfg->rules[cfg->rule_count];
  if(inet_pton(AF_INET, ip, &rule->addr) != 1) {
    return -2;
  }

  snprintf(rule->mask, sizeof(rule->mask), "%s", mask);
  normalize_domain(rule->mask, rule->mask, sizeof(rule->mask));
  snprintf(rule->text, sizeof(rule->text), "%s", ip);
  ++cfg->rule_count;
  return 0;
}

static void
config_add_exception(app_config_t *cfg, const char *mask) {
  exception_rule_t *rule;

  if(cfg->exception_count >= MAX_EXCEPTIONS) {
    return;
  }

  rule = &cfg->exceptions[cfg->exception_count];
  snprintf(rule->mask, sizeof(rule->mask), "%s", mask);
  normalize_domain(rule->mask, rule->mask, sizeof(rule->mask));
  ++cfg->exception_count;
}

static void
config_apply_builtin_exceptions(app_config_t *cfg) {
  cfg->exception_count = 0;
  config_add_exception(cfg, "feature.api.playstation.com");
  config_add_exception(cfg, "*.stun.playstation.net");
  config_add_exception(cfg, "stun.*.playstation.net");
  config_add_exception(cfg, "ena.net.playstation.net");
  config_add_exception(cfg, "post.net.playstation.net");
  config_add_exception(cfg, "gst.prod.dl.playstation.net");
}

static void
config_apply_builtin_upstreams(app_config_t *cfg) {
  cfg->upstream_count = 0;
  (void)config_add_upstream(cfg, "1.1.1.1");
  (void)config_add_upstream(cfg, "8.8.8.8");
  (void)config_add_upstream(cfg, "77.77.88.88");
}

static int
config_apply_builtin_overrides(app_config_t *cfg) {
  cfg->rule_count = 0;

  if(config_add_rule(cfg, "*.playstation.com", "0.0.0.0") != 0) {
    return -1;
  }
  if(config_add_rule(cfg, "*.playstation.com.*", "0.0.0.0") != 0) {
    return -1;
  }
  if(config_add_rule(cfg, "playstation.com", "0.0.0.0") != 0) {
    return -1;
  }
  if(config_add_rule(cfg, "*.playstation.net", "0.0.0.0") != 0) {
    return -1;
  }
  if(config_add_rule(cfg, "*.playstation.net.*", "0.0.0.0") != 0) {
    return -1;
  }
  if(config_add_rule(cfg, "*.psndl.net", "0.0.0.0") != 0) {
    return -1;
  }
  if(config_add_rule(cfg, "playstation.net", "0.0.0.0") != 0) {
    return -1;
  }
  if(config_add_rule(cfg, "psndl.net", "0.0.0.0") != 0) {
    return -1;
  }

  return 0;
}

static int
find_pid(const char *name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t mypid = getpid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, NULL, &buf_size, NULL, 0) != 0) {
    return -1;
  }

  buf = malloc(buf_size);
  if(buf == NULL) {
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, NULL, 0) != 0) {
    free(buf);
    return -1;
  }

  for(uint8_t *ptr = buf; ptr < (buf + buf_size);) {
    int ki_structsize = *(int *)ptr;
    pid_t ki_pid = *(pid_t *)&ptr[KI_PID_OFFSET];
    char *ki_tdname = (char *)&ptr[KI_TDNAME_OFFSET];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid) {
      pid = ki_pid;
    }
  }

  free(buf);
  return pid;
}

static int
terminate_existing_instances(const char *name) {
  pid_t pid;

  while((pid = find_pid(name)) > 0) {
    log_printf("[nanodns] terminating previous instance pid=%d name=%s\n", pid,
               name);
    if(kill(pid, SIGKILL) != 0) {
      log_errno("kill(previous instance)");
      return -1;
    }

    sleep(1);
  }

  return 0;
}

static int
ensure_runtime_dir_exists(const char *path) {
  struct stat st;

  if(stat(path, &st) == 0) {
    if(S_ISDIR(st.st_mode)) {
      return 0;
    }

    errno = ENOTDIR;
    return -1;
  }

  if(mkdir(path, 0777) != 0) {
    return -1;
  }

  return 1;
}

static int
ensure_default_config_exists(const char *path) {
  struct stat st;
  FILE *fp;

  if(stat(path, &st) == 0) {
    return 0;
  }

  fp = fopen(path, "w");
  if(fp == NULL) {
    return -1;
  }

  if(fputs(k_default_config, fp) == EOF) {
    fclose(fp);
    errno = EIO;
    return -1;
  }

  if(fclose(fp) != 0) {
    return -1;
  }

  return 1;
}

static int
load_config(const char *path, app_config_t *cfg) {
  enum {
    SECTION_NONE = 0,
    SECTION_GENERAL,
    SECTION_UPSTREAM,
    SECTION_OVERRIDES,
    SECTION_EXCEPTIONS,
  } section = SECTION_NONE;
  FILE *fp;
  char line[512];
  size_t line_no = 0;
  bool replace_upstreams = false;

  config_set_defaults(cfg);
  config_apply_builtin_upstreams(cfg);

  fp = fopen(path, "r");
  if(fp == NULL) {
    return -1;
  }

  cfg->rule_count = 0;
  cfg->exception_count = 0;

  while(fgets(line, sizeof(line), fp) != NULL) {
    char *s;
    char *eq;
    char *key;
    char *value;
    struct in_addr addr;

    ++line_no;

    s = trim(line);

    if(*s == '\0' || *s == '#' || *s == ';') {
      continue;
    }

    if(*s == '[') {
      char *end = strchr(s, ']');
      if(end == NULL) {
        continue;
      }

      *end = '\0';
      s = trim(s + 1);

      if(!strcasecmp(s, "general") || !strcasecmp(s, "settings")) {
        section = SECTION_GENERAL;
      } else if(!strcasecmp(s, "upstream") || !strcasecmp(s, "upstreams")) {
        section = SECTION_UPSTREAM;
      } else if(!strcasecmp(s, "override") || !strcasecmp(s, "overrides")) {
        section = SECTION_OVERRIDES;
      } else if(!strcasecmp(s, "exception") || !strcasecmp(s, "exceptions")) {
        section = SECTION_EXCEPTIONS;
      } else {
        section = SECTION_NONE;
      }

      continue;
    }

    strip_inline_comment(s);
    if(*s == '\0') {
      continue;
    }

    if(section == SECTION_EXCEPTIONS) {
      eq = strchr(s, '=');
      if(eq != NULL) {
        *eq = '\0';
      }

      key = trim(s);
      if(*key != '\0') {
        size_t before = cfg->exception_count;
        config_add_exception(cfg, key);
        if(cfg->exception_count == before) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu too many exception rules, ignoring '%s'\n",
                             path, line_no, key);
        }
      }
      continue;
    }

    eq = strchr(s, '=');
    if(eq == NULL) {
      continue;
    }

    *eq = '\0';
    key = trim(s);
    value = trim(eq + 1);

    if(*key == '\0' || *value == '\0') {
      continue;
    }

    if(section == SECTION_GENERAL ||
       (section == SECTION_NONE &&
        (!strcasecmp(key, "log") || !strcasecmp(key, "debug") ||
         !strcasecmp(key, "bind")))) {
      if(!strcasecmp(key, "log")) {
        snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", value);
      } else if(!strcasecmp(key, "debug")) {
        int parsed_debug;

        if(parse_int_strict(value, &parsed_debug) == 0) {
          cfg->debug_enabled = parsed_debug != 0 ? 1 : 0;
        } else {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid debug value '%s', keeping %s\n",
                             path, line_no, value,
                             cfg->debug_enabled ? "enabled" : "disabled");
        }
      } else if(!strcasecmp(key, "bind")) {
        if(config_set_bind_address(cfg, value) != 0) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid bind address '%s', keeping %s\n",
                             path, line_no, value, cfg->bind_text);
        }
      }
    } else if(section == SECTION_UPSTREAM) {
      if(!strcasecmp(key, "server") || !strcasecmp(key, "dns")) {
        if(!replace_upstreams) {
          cfg->upstream_count = 0;
          replace_upstreams = true;
        }

        if(inet_pton(AF_INET, value, &addr) != 1) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid upstream server '%s', ignoring\n",
                             path, line_no, value);
        } else if(config_add_upstream(cfg, value) != 0) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu too many upstream servers, ignoring '%s'\n",
                             path, line_no, value);
        }
      } else if(!strcasecmp(key, "timeout_ms")) {
        int parsed_timeout;

        if(parse_int_strict(value, &parsed_timeout) == 0 &&
            parsed_timeout > 0) {
          cfg->timeout_ms = parsed_timeout;
        } else {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid timeout_ms '%s', using %d\n",
                             path, line_no, value, DEFAULT_TIMEOUT_MS);
          cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
        }
      }
    } else if(section == SECTION_OVERRIDES) {
      int rc = config_add_rule(cfg, key, value);
      if(rc == -2) {
        config_add_warning(cfg,
                           "[nanodns] warning: %s:%zu invalid override IPv4 '%s' for mask '%s', ignoring\n",
                           path, line_no, value, key);
      } else if(rc != 0) {
        config_add_warning(cfg,
                           "[nanodns] warning: %s:%zu too many override rules, ignoring '%s=%s'\n",
                           path, line_no, key, value);
      }
    }
  }

  fclose(fp);

  if(cfg->upstream_count == 0) {
    config_apply_builtin_upstreams(cfg);
  }

  return 0;
}

static void
print_banner(void) {
  log_printf("============================================================\n");
  log_printf("%s v%s\n", APP_NAME, APP_VERSION);
  log_printf("Build: %s %s\n", __DATE__, __TIME__);
  log_printf("%s\n", APP_COPYRIGHT);
  log_printf("============================================================\n");
}

static int
send_startup_notification(const app_config_t *cfg) {
  notify_request_t req;
  int rc;

  memset(&req, 0, sizeof(req));
  rc = snprintf(req.message, sizeof(req.message), "%s v%s %s\nListening on %s:%d",
                APP_NAME, APP_VERSION, APP_COPYRIGHT, cfg->bind_text, DNS_PORT);
  if(rc < 0 || (size_t)rc >= sizeof(req.message)) {
    log_printf("[nanodns] failed to build startup notification message\n");
    return -1;
  }

  rc = sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
  if(rc != 0) {
    log_printf("[nanodns] sceKernelSendNotificationRequest failed: %d\n", rc);
    return -1;
  }

  return 0;
}

static int
elevate_privileges(void) {
  pid_t pid = getpid();

#if defined(PLATFORM_PS4)
  (void)pid;
  return 0;
#else
  if(kernel_set_ucred_authid(pid, PRIVILEGED_AUTHID) != 0) {
    log_printf("[nanodns] unable to change AuthID for pid %d\n", pid);
    return -1;
  }

  log_printf("[nanodns] AuthID updated for pid %d\n", pid);
  return 0;
#endif
}

static int64_t
now_ms(void) {
  struct timeval tv;

  if(gettimeofday(&tv, NULL) != 0) {
    return 0;
  }

  return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int
dns_expand_name(const uint8_t *packet, size_t packet_len, size_t *offset,
                char *output, size_t output_len) {
  size_t cursor = *offset;
  size_t end_offset = (size_t)-1;
  size_t out = 0;
  int jumps = 0;

  if(output_len == 0) {
    return -1;
  }

  while(cursor < packet_len) {
    uint8_t len = packet[cursor];

    if((len & 0xc0) == 0xc0) {
      uint16_t ptr;

      if(cursor + 1 >= packet_len) {
        return -1;
      }

      ptr = (uint16_t)(((len & 0x3f) << 8) | packet[cursor + 1]);
      if(ptr >= packet_len || ++jumps > 16) {
        return -1;
      }

      if(end_offset == (size_t)-1) {
        end_offset = cursor + 2;
      }

      cursor = ptr;
      continue;
    }

    if((len & 0xc0) != 0) {
      return -1;
    }

    ++cursor;
    if(len == 0) {
      output[out] = '\0';
      *offset = end_offset == (size_t)-1 ? cursor : end_offset;
      return 0;
    }

    if(cursor + len > packet_len) {
      return -1;
    }

    if(out != 0) {
      if(out + 1 >= output_len) {
        return -1;
      }
      output[out++] = '.';
    }

    if(out + len >= output_len) {
      return -1;
    }

    memcpy(&output[out], &packet[cursor], len);
    out += len;
    cursor += len;
  }

  return -1;
}

static int
dns_parse_question(const uint8_t *packet, size_t packet_len, dns_question_t *q) {
  size_t offset = 12;
  char normalized[MAX_DOMAIN_LEN];

  if(packet_len < 12) {
    return -1;
  }

  memset(q, 0, sizeof(*q));
  q->id = read_u16(&packet[0]);
  q->flags = read_u16(&packet[2]);
  q->qdcount = read_u16(&packet[4]);
  q->ancount = read_u16(&packet[6]);
  q->nscount = read_u16(&packet[8]);
  q->arcount = read_u16(&packet[10]);
  q->qname_offset = offset;

  if(q->qdcount == 0) {
    return -1;
  }

  if(dns_expand_name(packet, packet_len, &offset, q->qname, sizeof(q->qname)) !=
     0) {
    return -1;
  }

  if(offset + 4 > packet_len) {
    return -1;
  }

  q->qtype = read_u16(&packet[offset]);
  q->qclass = read_u16(&packet[offset + 2]);
  q->question_end = offset + 4;

  normalize_domain(q->qname, normalized, sizeof(normalized));
  snprintf(q->qname, sizeof(q->qname), "%s", normalized);

  return 0;
}

static int
domain_mask_match(const char *mask, const char *domain) {
  while(*mask != '\0') {
    if(*mask == '*') {
      do {
        ++mask;
      } while(*mask == '*');

      if(*mask == '\0') {
        return 1;
      }

      while(*domain != '\0') {
        if(domain_mask_match(mask, domain)) {
          return 1;
        }
        ++domain;
      }

      return 0;
    }

    if(*domain == '\0') {
      return 0;
    }

    if(*mask == '?') {
      ++mask;
      ++domain;
      continue;
    }

    if(*mask == '[') {
      bool negate = false;
      bool matched = false;
      const char *p = mask + 1;

      if(*p == '!' || *p == '^') {
        negate = true;
        ++p;
      }

      if(*p == ']') {
        matched = *domain == ']';
        ++p;
      }

      while(*p != '\0' && *p != ']') {
        unsigned char start;
        unsigned char end;

        if(*p == '\\' && p[1] != '\0') {
          start = (unsigned char)p[1];
          p += 2;
        } else {
          start = (unsigned char)*p++;
        }

        end = start;
        if(*p == '-' && p[1] != '\0' && p[1] != ']') {
          ++p;
          if(*p == '\\' && p[1] != '\0') {
            end = (unsigned char)p[1];
            p += 2;
          } else {
            end = (unsigned char)*p++;
          }
        }

        if((unsigned char)*domain >= start && (unsigned char)*domain <= end) {
          matched = true;
        }
      }

      if(*p != ']') {
        if(*mask != *domain) {
          return 0;
        }

        ++mask;
        ++domain;
        continue;
      }

      if(negate ? matched : !matched) {
        return 0;
      }

      mask = p + 1;
      ++domain;
      continue;
    }

    if(*mask == '\\' && mask[1] != '\0') {
      ++mask;
    }

    if(*mask != *domain) {
      return 0;
    }

    ++mask;
    ++domain;
  }

  return *domain == '\0';
}

static const override_rule_t *
find_matching_rule(const app_config_t *cfg, const char *domain) {
  for(size_t i = 0; i < cfg->rule_count; ++i) {
    if(domain_mask_match(cfg->rules[i].mask, domain)) {
      return &cfg->rules[i];
    }
  }

  return NULL;
}

static int
has_matching_exception(const app_config_t *cfg, const char *domain) {
  for(size_t i = 0; i < cfg->exception_count; ++i) {
    if(domain_mask_match(cfg->exceptions[i].mask, domain)) {
      return 1;
    }
  }

  return 0;
}

static int
build_error_response(const uint8_t *request, size_t request_len,
                     const dns_question_t *question, uint16_t rcode,
                     uint8_t *response, size_t response_cap,
                     size_t *response_len) {
  size_t question_len;

  if(response_cap < question->question_end) {
    return -1;
  }

  question_len = question->question_end - 12;
  memcpy(response, request, question->question_end);
  write_u16(&response[2],
            (uint16_t)(0x8000 | (question->flags & 0x0100) | 0x0080 |
                       (rcode & 0x000f)));
  write_u16(&response[4], 1);
  write_u16(&response[6], 0);
  write_u16(&response[8], 0);
  write_u16(&response[10], 0);
  *response_len = 12 + question_len;

  (void)request_len;
  return 0;
}

static int
build_nodata_response(const uint8_t *request, size_t request_len,
                      const dns_question_t *question, uint8_t *response,
                      size_t response_cap, size_t *response_len) {
  return build_error_response(request, request_len, question, 0, response,
                              response_cap, response_len);
}

static int
build_override_response(const uint8_t *request, const dns_question_t *question,
                        const struct in_addr *addr, uint8_t *response,
                        size_t response_cap, size_t *response_len) {
  size_t question_len = question->question_end - 12;
  size_t offset;

  if(response_cap < question->question_end + 16) {
    return -1;
  }

  memcpy(response, request, question->question_end);
  write_u16(&response[2],
            (uint16_t)(0x8000 | (question->flags & 0x0100) | 0x0080));
  write_u16(&response[4], 1);
  write_u16(&response[6], 1);
  write_u16(&response[8], 0);
  write_u16(&response[10], 0);

  offset = 12 + question_len;
  write_u16(&response[offset], 0xc00c);
  offset += 2;
  write_u16(&response[offset], 1);
  offset += 2;
  write_u16(&response[offset], 1);
  offset += 2;
  write_u32(&response[offset], OVERRIDE_TTL);
  offset += 4;
  write_u16(&response[offset], 4);
  offset += 2;
  memcpy(&response[offset], &addr->s_addr, 4);
  offset += 4;

  *response_len = offset;
  return 0;
}

static void
log_dns_query(const dns_question_t *question, const struct sockaddr_in *client) {
  char client_ip[INET_ADDRSTRLEN];

  if(inet_ntop(AF_INET, &client->sin_addr, client_ip, sizeof(client_ip)) ==
     NULL) {
    snprintf(client_ip, sizeof(client_ip), "<invalid>");
  }

  log_printf("[nanodns] query from=%s:%u id=0x%04x qname=%s qtype=%s(%u) qclass=%u\n",
             client_ip, ntohs(client->sin_port), question->id,
             question->qname[0] ? question->qname : ".", dns_type_to_string(question->qtype),
             question->qtype, question->qclass);
}

static void
log_answer_record(const uint8_t *packet, size_t packet_len, size_t *offset,
                  size_t index) {
  char name[MAX_DOMAIN_LEN];
  char target[MAX_DOMAIN_LEN];
  uint16_t type;
  uint16_t klass;
  uint16_t rdlength;
  uint32_t ttl;
  size_t rdata_offset;
  char ipbuf[INET6_ADDRSTRLEN];

  if(dns_expand_name(packet, packet_len, offset, name, sizeof(name)) != 0) {
    log_printf("[nanodns]   answer[%zu] <invalid owner name>\n", index);
    *offset = packet_len;
    return;
  }

  if(*offset + 10 > packet_len) {
    log_printf("[nanodns]   answer[%zu] <truncated rr header>\n", index);
    *offset = packet_len;
    return;
  }

  type = read_u16(&packet[*offset]);
  klass = read_u16(&packet[*offset + 2]);
  ttl = read_u32(&packet[*offset + 4]);
  rdlength = read_u16(&packet[*offset + 8]);
  *offset += 10;

  if(*offset + rdlength > packet_len) {
    log_printf("[nanodns]   answer[%zu] <truncated rr data>\n", index);
    *offset = packet_len;
    return;
  }

  rdata_offset = *offset;

  if(type == 1 && rdlength == 4 &&
     inet_ntop(AF_INET, &packet[rdata_offset], ipbuf, sizeof(ipbuf)) != NULL) {
    log_printf("[nanodns]   answer[%zu] name=%s type=A ttl=%u class=%u data=%s\n",
               index, name[0] ? name : ".", ttl, klass, ipbuf);
  } else if(type == 28 && rdlength == 16 &&
            inet_ntop(AF_INET6, &packet[rdata_offset], ipbuf,
                      sizeof(ipbuf)) != NULL) {
    log_printf("[nanodns]   answer[%zu] name=%s type=AAAA ttl=%u class=%u data=%s\n",
               index, name[0] ? name : ".", ttl, klass, ipbuf);
  } else if((type == 2 || type == 5 || type == 12) &&
            dns_expand_name(packet, packet_len, &rdata_offset, target,
                            sizeof(target)) == 0) {
    log_printf("[nanodns]   answer[%zu] name=%s type=%s ttl=%u class=%u data=%s\n",
               index, name[0] ? name : ".", dns_type_to_string(type), ttl, klass,
               target[0] ? target : ".");
  } else {
    log_printf("[nanodns]   answer[%zu] name=%s type=%s(%u) ttl=%u class=%u rdlen=%u\n",
               index, name[0] ? name : ".", dns_type_to_string(type), type, ttl,
               klass, rdlength);
  }

  *offset += rdlength;
}

static void
log_dns_response(const uint8_t *packet, size_t packet_len, const char *via) {
  dns_question_t question;
  uint16_t flags;
  uint16_t rcode;
  size_t offset;

  if(dns_parse_question(packet, packet_len, &question) != 0) {
    log_printf("[nanodns] response via=%s <failed to parse>\n", via);
    return;
  }

  flags = read_u16(&packet[2]);
  rcode = (uint16_t)(flags & 0x000f);

  log_printf("[nanodns] response via=%s id=0x%04x qname=%s qtype=%s(%u) rcode=%s(%u) answers=%u authority=%u additional=%u\n",
             via, question.id, question.qname[0] ? question.qname : ".",
             dns_type_to_string(question.qtype), question.qtype,
             dns_rcode_to_string(rcode), rcode, read_u16(&packet[6]),
             read_u16(&packet[8]), read_u16(&packet[10]));

  offset = question.question_end;
  for(size_t i = 0; i < question.ancount && offset < packet_len; ++i) {
    log_answer_record(packet, packet_len, &offset, i);
  }
}

static int
open_upstream_socket(const upstream_t *upstream) {
  struct sockaddr_in upstream_addr;
  int fd;

  memset(&upstream_addr, 0, sizeof(upstream_addr));
  upstream_addr.sin_family = AF_INET;
  upstream_addr.sin_port = htons(DNS_PORT);
  upstream_addr.sin_addr = upstream->addr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd < 0) {
    log_printf("[nanodns] upstream %s socket failed: %s\n", upstream->text,
               strerror(errno));
    return -1;
  }

  if(connect(fd, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) !=
     0) {
    log_printf("[nanodns] upstream %s connect failed: %s\n", upstream->text,
               strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

static void
close_upstream_socket(int *fd) {
  if(*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
}

static void
close_upstream_sockets(int *fds, size_t count) {
  for(size_t i = 0; i < count; ++i) {
    close_upstream_socket(&fds[i]);
  }
}

static void
invalidate_server_socket(int *server_fd, struct pollfd *pfd) {
  if(*server_fd >= 0) {
    close(*server_fd);
    *server_fd = -1;
  }

  pfd->fd = -1;
  pfd->events = POLLIN;
  pfd->revents = 0;
}

static int
open_server_socket(const app_config_t *cfg) {
  struct sockaddr_in listen_addr;
  int fd;
  int reuse = 1;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd < 0) {
    log_errno("socket(server)");
    return -1;
  }

  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
    log_errno("setsockopt(SO_REUSEADDR)");
  }

  memset(&listen_addr, 0, sizeof(listen_addr));
  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(DNS_PORT);
  listen_addr.sin_addr = cfg->bind_addr;

  if(bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) != 0) {
    log_printf("[nanodns] bind(%s:%d) failed: %s\n", cfg->bind_text, DNS_PORT,
               strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

static int
drain_upstream_socket(int fd) {
  uint8_t discard[MAX_DNS_PACKET];
  struct pollfd pfd;

  pfd.fd = fd;
  pfd.events = POLLIN;

  while(true) {
    ssize_t nread;

    pfd.revents = 0;
    if(poll(&pfd, 1, 0) <= 0) {
      return 0;
    }

    if((pfd.revents & POLLIN) == 0) {
      return (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0 ? 0 : -1;
    }

    nread = recv(fd, discard, sizeof(discard), 0);
    if(nread <= 0) {
      return -1;
    }
  }
}

static int
server_socket_needs_reopen(int err) {
  switch(err) {
  case EBADF:
  case EINVAL:
  case ENOTSOCK:
    return 1;
  default:
    return 0;
  }
}

static int
forward_query_to_upstream(const app_config_t *cfg, const uint8_t *request,
                          size_t request_len, uint16_t request_id,
                          int *upstream_fds,
                          uint8_t *response, size_t response_cap,
                          size_t *response_len, char *via, size_t via_len) {
  int64_t deadline_ms;

  deadline_ms = now_ms() + cfg->timeout_ms;

  for(size_t i = 0; i < cfg->upstream_count; ++i) {
    struct pollfd pfd;
    int fd;
    int poll_rc;

    fd = upstream_fds[i];
    if(fd < 0) {
      fd = open_upstream_socket(&cfg->upstreams[i]);
      if(fd < 0) {
        continue;
      }

      upstream_fds[i] = fd;
    }

    if(drain_upstream_socket(fd) != 0) {
      log_printf("[nanodns] upstream %s drain failed, reconnecting\n",
                 cfg->upstreams[i].text);
      close_upstream_socket(&upstream_fds[i]);
      fd = open_upstream_socket(&cfg->upstreams[i]);
      if(fd < 0) {
        continue;
      }

      upstream_fds[i] = fd;
    }

    if(send(fd, request, request_len, 0) < 0) {
      log_printf("[nanodns] upstream %s send failed: %s\n",
                 cfg->upstreams[i].text, strerror(errno));
      close_upstream_socket(&upstream_fds[i]);
      continue;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    while(true) {
      int64_t timeout_ms = deadline_ms - now_ms();

      if(timeout_ms <= 0) {
        log_printf("[nanodns] upstream %s timed out\n", cfg->upstreams[i].text);
        close_upstream_socket(&upstream_fds[i]);
        break;
      }

      poll_rc = poll(&pfd, 1, (int)timeout_ms);
      if(poll_rc == 0) {
        log_printf("[nanodns] upstream %s timed out\n",
                   cfg->upstreams[i].text);
        close_upstream_socket(&upstream_fds[i]);
        break;
      }

      if(poll_rc < 0) {
        if(errno == EINTR) {
          continue;
        }

        log_printf("[nanodns] upstream %s poll failed: %s\n",
                   cfg->upstreams[i].text, strerror(errno));
        close_upstream_socket(&upstream_fds[i]);
        break;
      }

      if((pfd.revents & POLLIN) != 0) {
        ssize_t nread = recv(fd, response, response_cap, 0);
        if(nread < 0) {
          log_printf("[nanodns] upstream %s recv failed: %s\n",
                     cfg->upstreams[i].text, strerror(errno));
          close_upstream_socket(&upstream_fds[i]);
          break;
        } else if((size_t)nread < 12) {
          log_printf("[nanodns] upstream %s returned short packet (%zd bytes)\n",
                     cfg->upstreams[i].text, nread);
          close_upstream_socket(&upstream_fds[i]);
          break;
        } else if(read_u16(response) != request_id) {
          log_printf("[nanodns] upstream %s returned mismatched id 0x%04x\n",
                     cfg->upstreams[i].text, read_u16(response));
          close_upstream_socket(&upstream_fds[i]);
          break;
        } else {
          *response_len = (size_t)nread;
          snprintf(via, via_len, "%s", cfg->upstreams[i].text);
          return 0;
        }
      } else if((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        log_printf("[nanodns] upstream %s poll events=0x%x\n",
                   cfg->upstreams[i].text, pfd.revents);
        close_upstream_socket(&upstream_fds[i]);
        break;
      }

      pfd.revents = 0;
    }
  }

  return -1;
}

static int
net_init(void) {
  if(sceNetInit() != 0) {
    errno = EIO;
    log_errno("sceNetInit");
    return -1;
  }

  g_libnet_mem_id = sceNetPoolCreate("nanodns", 64 * 1024, 0);
  if(g_libnet_mem_id < 0) {
    errno = EIO;
    log_errno("sceNetPoolCreate");
    if(sceNetTerm() != 0) {
      errno = EIO;
      log_errno("sceNetTerm");
    }
    return -1;
  }

  return 0;
}

static void
net_fini(void) {
  if(g_libnet_mem_id >= 0) {
    if(sceNetPoolDestroy(g_libnet_mem_id) != 0) {
      errno = EIO;
      log_errno("sceNetPoolDestroy");
    }
    g_libnet_mem_id = -1;
  }

  if(sceNetTerm() != 0) {
    errno = EIO;
    log_errno("sceNetTerm");
  }
}

static void
on_signal(int signo) {
  (void)signo;
  g_running = 0;
}

int
main(void) {
  app_config_t cfg;
  int upstream_fds[MAX_UPSTREAMS];
  int server_fd = -1;
  struct pollfd pfd;
  int config_state;
  int config_errno = 0;
  int config_loaded = 0;
  int data_dir_state;
  int data_dir_errno = 0;

  for(size_t i = 0; i < MAX_UPSTREAMS; ++i) {
    upstream_fds[i] = -1;
  }

  (void)syscall(SYS_thr_set_name, -1, PAYLOAD_EXEC_NAME);

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  data_dir_state = ensure_runtime_dir_exists(DATA_DIR);
  if(data_dir_state < 0) {
    data_dir_errno = errno;
  }

  config_state = ensure_default_config_exists(CONFIG_PATH);
  if(config_state < 0) {
    config_errno = errno;
  }

  if(load_config(CONFIG_PATH, &cfg) != 0) {
    config_set_defaults(&cfg);
    config_apply_builtin_upstreams(&cfg);
    (void)config_apply_builtin_overrides(&cfg);
    config_apply_builtin_exceptions(&cfg);
  } else {
    config_loaded = 1;
  }

  (void)logger_init(&cfg);
  print_banner();

  for(size_t i = 0; i < cfg.warning_count; ++i) {
    log_printf("%s", cfg.warnings[i].text);
  }

  if(data_dir_state == 1) {
    log_printf("[nanodns] created runtime directory %s\n", DATA_DIR);
  } else if(data_dir_state < 0) {
    log_printf("[nanodns] could not create %s: %s\n", DATA_DIR,
               strerror(data_dir_errno));
  }

  if(config_state == 1) {
    log_printf("[nanodns] created default config at %s\n", CONFIG_PATH);
  } else if(config_state < 0) {
    log_printf("[nanodns] could not create %s: %s\n", CONFIG_PATH,
               strerror(config_errno));
  }

  if(!config_loaded) {
    log_printf("[nanodns] could not fully load %s, using fallback defaults\n",
               CONFIG_PATH);
  }

  if(g_log_file != NULL) {
    log_printf("[nanodns] log file: %s\n", cfg.log_path);
  }
  log_printf("[nanodns] debug output: %s\n",
             cfg.debug_enabled ? "enabled" : "disabled");
  log_printf("[nanodns] config loaded: %zu upstream(s), %zu rule(s), %zu exception(s), timeout=%dms\n",
             cfg.upstream_count, cfg.rule_count, cfg.exception_count,
             cfg.timeout_ms);

  for(size_t i = 0; i < cfg.upstream_count; ++i) {
    log_printf("[nanodns] upstream[%zu] = %s\n", i, cfg.upstreams[i].text);
  }

  for(size_t i = 0; i < cfg.rule_count; ++i) {
    log_printf("[nanodns] rule[%zu] = %s -> %s\n", i, cfg.rules[i].mask,
               cfg.rules[i].text);
  }

  for(size_t i = 0; i < cfg.exception_count; ++i) {
    log_printf("[nanodns] exception[%zu] = %s\n", i, cfg.exceptions[i].mask);
  }

  if(terminate_existing_instances(PAYLOAD_EXEC_NAME) != 0) {
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    logger_fini();
    return EXIT_FAILURE;
  }

  if(elevate_privileges() != 0) {
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    logger_fini();
    return EXIT_FAILURE;
  }

  if(net_init() != 0) {
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    logger_fini();
    return 1;
  }

  server_fd = open_server_socket(&cfg);
  if(server_fd < 0) {
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    net_fini();
    logger_fini();
    return 1;
  }

  log_printf("[nanodns] listening on %s:%d\n", cfg.bind_text, DNS_PORT);

  pfd.fd = server_fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  (void)send_startup_notification(&cfg);

  while(g_running) {
    uint8_t request[MAX_DNS_PACKET];
    uint8_t response[MAX_DNS_PACKET];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    dns_question_t question;
    ssize_t received;
    int poll_rc;

    if(server_fd < 0) {
      log_printf("[nanodns] attempting to restore listening socket on %s:%d\n",
                 cfg.bind_text, DNS_PORT);
      server_fd = open_server_socket(&cfg);
      if(server_fd < 0) {
        sleep(1);
        continue;
      }

      pfd.fd = server_fd;
      pfd.events = POLLIN;
      pfd.revents = 0;
      log_printf("[nanodns] listening socket restored on %s:%d\n",
                 cfg.bind_text, DNS_PORT);
    }

    poll_rc = poll(&pfd, 1, 1000);
    if(poll_rc == 0) {
      continue;
    }

    if(poll_rc < 0) {
      if(errno == EINTR) {
        continue;
      }

      log_errno("poll(server)");
      if(server_socket_needs_reopen(errno)) {
        invalidate_server_socket(&server_fd, &pfd);
      }
      continue;
    }

    if((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      log_printf("[nanodns] listening socket poll events=0x%x, recreating\n",
                 pfd.revents);
      invalidate_server_socket(&server_fd, &pfd);
      continue;
    }

    if((pfd.revents & POLLIN) == 0) {
      pfd.revents = 0;
      continue;
    }

    received = recvfrom(server_fd, request, sizeof(request), 0,
                        (struct sockaddr *)&client_addr, &client_len);
    if(received < 0) {
      if(errno == EINTR || errno == EAGAIN) {
        pfd.revents = 0;
        continue;
      }

      log_errno("recvfrom(client)");
      if(server_socket_needs_reopen(errno)) {
        invalidate_server_socket(&server_fd, &pfd);
      } else {
        pfd.revents = 0;
      }
      continue;
    }

    if(dns_parse_question(request, (size_t)received, &question) != 0) {
      log_printf("[nanodns] received malformed DNS packet (%zd bytes)\n",
                 received);
      continue;
    }

    log_dns_query(&question, &client_addr);

    if(question.qdcount == 1 && question.qclass == 1) {
      const override_rule_t *rule = NULL;

      if(has_matching_exception(&cfg, question.qname)) {
        log_printf("[nanodns] exception matched, bypassing override for %s\n",
                   question.qname);
      } else {
        rule = find_matching_rule(&cfg, question.qname);
      }

      if(rule != NULL) {
        size_t response_len;
        int build_rc;
        const char *response_via;

        log_printf("[nanodns] override matched %s -> %s for %s\n", rule->mask,
                   rule->text, question.qname);

        if(question.qtype == 1 || question.qtype == 255) {
          build_rc = build_override_response(request, &question, &rule->addr,
                                             response, sizeof(response),
                                             &response_len);
          response_via = "override";
        } else {
          build_rc = build_nodata_response(request, (size_t)received, &question,
                                           response, sizeof(response),
                                           &response_len);
          response_via = "override-nodata";
        }

        if(build_rc == 0) {
          if(sendto(server_fd, response, response_len, 0,
                    (struct sockaddr *)&client_addr, client_len) < 0) {
            log_errno("sendto(client, override-local)");
          } else {
            log_dns_response(response, response_len, response_via);
          }
          continue;
        }

        if(build_error_response(request, (size_t)received, &question, 2,
                                response, sizeof(response),
                                &response_len) == 0) {
          if(sendto(server_fd, response, response_len, 0,
                    (struct sockaddr *)&client_addr, client_len) < 0) {
            log_errno("sendto(client, override-servfail)");
          } else {
            log_dns_response(response, response_len, "override-servfail");
          }
          continue;
        }

        log_printf("[nanodns] failed to build override response for %s\n",
                   question.qname);
      }
    }

    {
      size_t response_len = 0;
      char via[INET_ADDRSTRLEN];

      if(forward_query_to_upstream(&cfg, request, (size_t)received, question.id,
                                   upstream_fds, response, sizeof(response),
                                   &response_len,
                                   via, sizeof(via)) == 0) {
        if(sendto(server_fd, response, response_len, 0,
                  (struct sockaddr *)&client_addr, client_len) < 0) {
          log_errno("sendto(client, upstream)");
        } else {
          log_dns_response(response, response_len, via);
        }
      } else {
        size_t response_len = 0;

        log_printf("[nanodns] all upstreams failed for %s\n", question.qname);
        if(build_error_response(request, (size_t)received, &question, 2,
                                response, sizeof(response),
                                &response_len) == 0) {
          if(sendto(server_fd, response, response_len, 0,
                    (struct sockaddr *)&client_addr, client_len) < 0) {
            log_errno("sendto(client, servfail)");
          } else {
            log_dns_response(response, response_len, "local-servfail");
          }
        }
      }
    }

    pfd.revents = 0;
  }

  log_printf("[nanodns] shutting down\n");
  invalidate_server_socket(&server_fd, &pfd);
  close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
  net_fini();
  logger_fini();
  return 0;
}

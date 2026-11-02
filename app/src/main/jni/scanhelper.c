#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#define SCANFILE "/data/local/tmp/.ms_scan.bin"
#define TMPFILE  "/data/local/tmp/.ms_scan.tmp"
#define CHUNK    1048576
#define MAXREG   8192
#define MAXFREEZE 256
#define MAXHITS  40000000ULL

/* types: 0=i8 1=i16 2=i32 3=i64 4=f32 5=f64 */
/* preds: 0=eq 1=ne 2=gt 3=lt 4=changed 5=unchanged 6=inc 7=dec */

typedef struct { uint64_t start, end; } Region;
typedef struct { uint64_t addr, val; } Rec;
typedef struct { uint64_t addr, val; int type; int on; } Freeze;

static Region g_reg[MAXREG];
static int g_nreg = 0;
static int g_mem = -1;
static int g_pid = 0;
static uint64_t g_count = 0;
static Freeze g_frz[MAXFREEZE];
static int g_nfrz = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int tsize(int t) {
    switch (t) {
        case 0: return 1;
        case 1: return 2;
        case 2: return 4;
        case 3: return 8;
        case 4: return 4;
        case 5: return 8;
    }
    return 4;
}

static uint64_t mask_for(int t) {
    int n = tsize(t);
    if (n >= 8) return ~0ULL;
    return (1ULL << (n * 8)) - 1;
}

static uint64_t load_buf(const unsigned char *p, int t) {
    uint64_t v = 0;
    memcpy(&v, p, tsize(t));
    return v;
}

static int64_t sv(uint64_t v, int t) {
    switch (t) {
        case 0: return (int8_t)v;
        case 1: return (int16_t)v;
        case 2: return (int32_t)v;
        default: return (int64_t)v;
    }
}

static double dv(uint64_t v, int t) {
    if (t == 4) {
        uint32_t u = (uint32_t)v;
        float f;
        memcpy(&f, &u, 4);
        return (double)f;
    }
    double d;
    memcpy(&d, &v, 8);
    return d;
}

static bool eqv(uint64_t a, uint64_t b, int t) {
    int n = tsize(t);
    if (n == 4 && t == 4) { return dv(a, 4) == dv(b, 4); }
    if (n == 8 && t == 5) { return dv(a, 5) == dv(b, 5); }
    return sv(a, t) == sv(b, t);
}

static bool cmp_pred(uint64_t cur, uint64_t old, uint64_t tgt, int t, int pred) {
    switch (pred) {
        case 0: return eqv(cur, tgt, t);
        case 1: return !eqv(cur, tgt, t);
        case 2: return t >= 4 ? dv(cur, t) > dv(tgt, t) : sv(cur, t) > sv(tgt, t);
        case 3: return t >= 4 ? dv(cur, t) < dv(tgt, t) : sv(cur, t) < sv(tgt, t);
        case 4: return !eqv(cur, old, t);
        case 5: return eqv(cur, old, t);
        case 6: return t >= 4 ? dv(cur, t) > dv(old, t) : sv(cur, t) > sv(old, t);
        case 7: return t >= 4 ? dv(cur, t) < dv(old, t) : sv(cur, t) < sv(old, t);
    }
    return false;
}

static int find_pid(const char *pkg) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        char p[64];
        snprintf(p, sizeof p, "/proc/%s/cmdline", e->d_name);
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        char buf[256];
        ssize_t n = read(fd, buf, sizeof buf - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = 0;
        if (strcmp(buf, pkg) == 0) { found = atoi(e->d_name); break; }
    }
    closedir(d);
    return found;
}

static void load_regions(void) {
    g_nreg = 0;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", g_pid);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f) && g_nreg < MAXREG) {
        uint64_t a, b;
        char perms[8];
        char rest[400] = "";
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %399[^\n]", &a, &b, perms, rest) < 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p') continue;
        if (strstr(rest, "[vvar") || strstr(rest, "[vsyscall") || strstr(rest, "[vdso")) continue;
        if (strstr(rest, "/dev/") || strstr(rest, "/memfd") || strstr(rest, "kgsl") || strstr(rest, "/dmabuf")) continue;
        if (b - a < 4) continue;
        g_reg[g_nreg].start = a;
        g_reg[g_nreg].end = b;
        g_nreg++;
    }
    fclose(f);
}

static bool is_valid(uint64_t addr) {
    int lo = 0, hi = g_nreg - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (addr < g_reg[mid].start) hi = mid - 1;
        else if (addr >= g_reg[mid].end) lo = mid + 1;
        else return true;
    }
    return false;
}

static bool read_val(uint64_t addr, int t, uint64_t *out) {
    if (g_mem < 0) return false;
    uint64_t v = 0;
    ssize_t n = pread(g_mem, &v, tsize(t), (off_t)addr);
    if (n != tsize(t)) return false;
    *out = v;
    return true;
}

static void cmd_maps(void) {
    load_regions();
    for (int i = 0; i < g_nreg; i++) printf("%llx-%llx\n", (unsigned long long)g_reg[i].start, (unsigned long long)g_reg[i].end);
    printf("END\n");
}

static void cmd_scan1(int t, uint64_t target) {
    if (g_mem < 0) { printf("ERR no process\n"); return; }
    load_regions();
    if (g_nreg == 0) { printf("ERR no readable memory\n"); return; }

    target &= mask_for(t);
    int out = open(SCANFILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { printf("ERR scanfile\n"); return; }

    size_t ts = (size_t)tsize(t);
    unsigned char *buf = malloc(CHUNK);
    Rec *batch = malloc(sizeof(Rec) * 8192);
    uint64_t total = 0;
    int bn = 0;

    for (int r = 0; r < g_nreg && total < MAXHITS; r++) {
        uint64_t a = (g_reg[r].start + ts - 1) & ~(uint64_t)(ts - 1);
        while (a < g_reg[r].end) {
            uint64_t want = g_reg[r].end - a;
            if (want > CHUNK) want = CHUNK;
            ssize_t got = pread(g_mem, buf, want, (off_t)a);
            if (got <= 0) break;
            for (ssize_t off = 0; off + (ssize_t)ts <= got; off += (ssize_t)ts) {
                uint64_t cur = load_buf(buf + off, t);
                if (eqv(cur, target, t)) {
                    batch[bn].addr = a + (uint64_t)off;
                    batch[bn].val = cur;
                    if (++bn == 8192) {
                        write(out, batch, (size_t)bn * sizeof(Rec));
                        total += (uint64_t)bn;
                        bn = 0;
                    }
                }
            }
            a += (uint64_t)got;
        }
    }
    if (bn > 0) {
        write(out, batch, (size_t)bn * sizeof(Rec));
        total += (uint64_t)bn;
    }
    close(out);
    free(buf);
    free(batch);
    g_count = total;
    printf("OK %llu\n", (unsigned long long)total);
}

static void cmd_next(int t, int pred, uint64_t target) {
    if (g_mem < 0) { printf("ERR no process\n"); return; }
    target &= mask_for(t);
    load_regions();

    int in = open(SCANFILE, O_RDONLY);
    if (in < 0) { printf("ERR no scan\n"); return; }
    int out = open(TMPFILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); printf("ERR tmp\n"); return; }

    Rec r;
    Rec *batch = malloc(sizeof(Rec) * 8192);
    uint64_t kept = 0;
    int bn = 0;
    size_t ts = (size_t)tsize(t);

    while (read(in, &r, sizeof r) == (ssize_t)sizeof r) {
        if (!is_valid(r.addr)) continue;
        uint64_t cur;
        if (g_mem < 0 || pread(g_mem, &cur, ts, (off_t)r.addr) != (ssize_t)ts) continue;
        if (!cmp_pred(cur, r.val, target, t, pred)) continue;
        batch[bn].addr = r.addr;
        batch[bn].val = cur;
        if (++bn == 8192) {
            write(out, batch, (size_t)bn * sizeof(Rec));
            kept += (uint64_t)bn;
            bn = 0;
        }
    }
    if (bn > 0) {
        write(out, batch, (size_t)bn * sizeof(Rec));
        kept += (uint64_t)bn;
    }
    close(in);
    close(out);
    free(batch);
    rename(TMPFILE, SCANFILE);
    g_count = kept;
    printf("OK %llu\n", (unsigned long long)kept);
}

static void cmd_results(uint64_t start, uint64_t n, int t) {
    int fd = open(SCANFILE, O_RDONLY);
    if (fd < 0) { printf("ERR no scan\nEND\n"); return; }
    if (start > g_count) start = g_count;
    if (n > 500) n = 500;
    if (start + n > g_count) n = g_count - start;

    Rec r;
    for (uint64_t i = 0; i < n; i++) {
        if (pread(fd, &r, sizeof r, (off_t)((start + i) * sizeof(Rec))) != (ssize_t)sizeof r) break;
        uint64_t cur = r.val;
        if (g_mem >= 0) {
            uint64_t live = 0;
            if (pread(g_mem, &live, (size_t)tsize(t), (off_t)r.addr) == tsize(t)) cur = live;
        }
        printf("%llx %lld\n", (unsigned long long)r.addr, (long long)cur);
    }
    close(fd);
    printf("END\n");
}

static void cmd_write(uint64_t addr, int t, uint64_t val) {
    if (g_mem < 0) { printf("ERR no process\n"); return; }
    val &= mask_for(t);
    if (pwrite(g_mem, &val, tsize(t), (off_t)addr) != tsize(t)) { printf("ERR write failed\n"); return; }
    printf("OK\n");
}

static void cmd_freeze(uint64_t addr, int t, uint64_t val) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nfrz; i++) {
        if (g_frz[i].addr == addr) {
            g_frz[i].val = val & mask_for(t);
            g_frz[i].type = t;
            g_frz[i].on = 1;
            pthread_mutex_unlock(&g_lock);
            printf("OK\n");
            return;
        }
    }
    if (g_nfrz >= MAXFREEZE) { pthread_mutex_unlock(&g_lock); printf("ERR freeze full\n"); return; }
    g_frz[g_nfrz].addr = addr;
    g_frz[g_nfrz].val = val & mask_for(t);
    g_frz[g_nfrz].type = t;
    g_frz[g_nfrz].on = 1;
    g_nfrz++;
    pthread_mutex_unlock(&g_lock);
    printf("OK\n");
}

static void cmd_unfreeze(uint64_t addr) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nfrz; i++) {
        if (g_frz[i].addr == addr) { g_frz[i].on = 0; break; }
    }
    pthread_mutex_unlock(&g_lock);
    printf("OK\n");
}

static void *freezer(void *arg) {
    (void)arg;
    struct timespec ts = { 0, 20 * 1000 * 1000 };
    for (;;) {
        pthread_mutex_lock(&g_lock);
        if (g_mem >= 0) {
            for (int i = 0; i < g_nfrz; i++) {
                if (!g_frz[i].on) continue;
                pwrite(g_mem, &g_frz[i].val, tsize(g_frz[i].type), (off_t)g_frz[i].addr);
            }
        }
        pthread_mutex_unlock(&g_lock);
        nanosleep(&ts, NULL);
    }
    return NULL;
}


static int parse_pattern(const char *src, unsigned char *bytes, unsigned char *mask, int cap) {
    int n = 0; const char *p = src;
    while (*p && n < cap) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (p[0] == '?' && (p[1] == '?' || p[1] == '\0' || p[1] == ' ')) {
            bytes[n] = 0; mask[n] = 0; n++; p += (p[1] == '?' ? 2 : 1); continue;
        }
        char tok[3] = {0};
        if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1])) return -1;
        tok[0] = p[0]; tok[1] = p[1];
        bytes[n] = (unsigned char)strtoul(tok, NULL, 16); mask[n] = 1; n++; p += 2;
        if (*p && *p != ' ' && *p != '\t') return -1;
    }
    return n;
}

static void cmd_pattern(const char *pattern, int is_text) {
    if (g_mem < 0) { printf("ERR no process\nEND\n"); return; }
    unsigned char pat[256], mask[256]; int pn = 0;
    if (is_text) {
        pn = (int)strlen(pattern);
        if (pn <= 0 || pn > 256) { printf("ERR text length must be 1..256 bytes\nEND\n"); return; }
        memcpy(pat, pattern, (size_t)pn); memset(mask, 1, (size_t)pn);
    } else {
        pn = parse_pattern(pattern, pat, mask, 256);
        if (pn <= 0) { printf("ERR invalid AOB pattern; use pairs like 2A ?? FF\nEND\n"); return; }
    }
    load_regions();
    unsigned char *buf = malloc(CHUNK + 256);
    if (!buf) { printf("ERR out of memory\nEND\n"); return; }
    int hits = 0;
    const size_t overlap = (size_t)pn - 1;
    for (int ri = 0; ri < g_nreg && hits < 500; ri++) {
        uint64_t base = g_reg[ri].start;
        while (base < g_reg[ri].end && hits < 500) {
            size_t remaining = (size_t)(g_reg[ri].end - base);
            size_t want = remaining > CHUNK + overlap ? CHUNK + overlap : remaining;
            ssize_t got = pread(g_mem, buf, want, (off_t)base);
            if (got < pn) break;
            for (ssize_t i = 0; i + pn <= got && hits < 500; i++) {
                int j; for (j = 0; j < pn; j++) if (mask[j] && buf[i+j] != pat[j]) break;
                if (j == pn) { printf("%llx\n", (unsigned long long)(base + (uint64_t)i)); hits++; }
            }
            if ((size_t)got < want) break;
            size_t advance = (size_t)got - overlap;
            if (advance == 0) break;
            base += (uint64_t)advance;
        }
    }
    free(buf); printf("END\n");
}

static void cmd_ptrscan(uint64_t target) {
    if (g_mem < 0) { printf("ERR no process\nEND\n"); return; }
    load_regions();
    unsigned char *buf = malloc(CHUNK + 8);
    if (!buf) { printf("ERR out of memory\nEND\n"); return; }
    int hits = 0;
    for (int ri = 0; ri < g_nreg && hits < 500; ri++) {
        uint64_t base = (g_reg[ri].start + 7ULL) & ~7ULL;
        while (base + 8 <= g_reg[ri].end && hits < 500) {
            size_t want = (size_t)(g_reg[ri].end - base);
            if (want > CHUNK) want = CHUNK;
            ssize_t got = pread(g_mem, buf, want, (off_t)base);
            if (got < 8) break;
            for (ssize_t i = 0; i + 8 <= got && hits < 500; i += 8) {
                uint64_t value; memcpy(&value, buf + i, 8);
                if (value == target) { printf("%llx\n", (unsigned long long)(base + (uint64_t)i)); hits++; }
            }
            if ((size_t)got < want) break;
            base += (uint64_t)got;
            base = (base + 7ULL) & ~7ULL;
        }
    }
    free(buf); printf("END\n");
}

static void cmd_pointer(uint64_t addr) {
    if (g_mem < 0) { printf("ERR no process\n"); return; }
    load_regions();
    uint64_t value = 0;
    if (!is_valid(addr) || pread(g_mem, &value, sizeof(value), (off_t)addr) != (ssize_t)sizeof(value)) {
        printf("ERR address is not readable in attached process\n"); return;
    }
    printf("OK %llx %s\n", (unsigned long long)value, is_valid(value) ? "mapped" : "unmapped");
}

static bool valid_range(uint64_t addr, size_t len) {
    if (len == 0 || addr > UINT64_MAX - len) return false;
    for (int i = 0; i < g_nreg; i++) {
        if (addr >= g_reg[i].start && addr + len <= g_reg[i].end) return true;
    }
    return false;
}

static void cmd_readhex(uint64_t addr, size_t len) {
    if (g_mem < 0) { printf("ERR no process\n"); return; }
    if (len == 0 || len > 64) { printf("ERR length must be 1..64 bytes\n"); return; }
    load_regions();
    unsigned char data[64];
    if (!valid_range(addr, len) || pread(g_mem, data, len, (off_t)addr) != (ssize_t)len) {
        printf("ERR address range is not readable\n"); return;
    }
    printf("OK ");
    for (size_t i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

static void cmd_writehex(uint64_t addr, const char *hex) {
    size_t chars = strlen(hex);
    if (g_mem < 0) { printf("ERR no process\n"); return; }
    if (chars == 0 || (chars & 1) || chars > 128) { printf("ERR hex data must be 1..64 complete bytes\n"); return; }
    size_t len = chars / 2;
    unsigned char data[64];
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)hex[i*2]) || !isxdigit((unsigned char)hex[i*2+1])) {
            printf("ERR invalid hex data\n"); return;
        }
        char pair[3] = { hex[i*2], hex[i*2+1], 0 };
        data[i] = (unsigned char)strtoul(pair, NULL, 16);
    }
    load_regions();
    if (!valid_range(addr, len) || pwrite(g_mem, data, len, (off_t)addr) != (ssize_t)len) {
        printf("ERR address range is not writable\n"); return;
    }
    printf("OK\n");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    pthread_t th;
    pthread_create(&th, NULL, freezer, NULL);

    printf("READY\n");

    char line[512];
    while (fgets(line, sizeof line, stdin)) {
        char cmd[32];
        if (sscanf(line, "%31s", cmd) != 1) continue;

        if (!strcmp(cmd, "quit")) break;

        if (!strcmp(cmd, "pid")) {
            char pkg[256];
            if (sscanf(line, "%*s %255s", pkg) != 1) { printf("ERR usage\n"); continue; }
            /* Accept a package identifier only; no shell is involved in this parser. */
            bool safe_pkg = true;
            for (const char *q = pkg; *q; q++) {
                if (!(isalnum((unsigned char)*q) || *q == '.' || *q == '_')) { safe_pkg = false; break; }
            }
            if (!safe_pkg || strchr(pkg, '.') == NULL) {
                printf("ERR invalid package name\n");
                continue;
            }
            int p = find_pid(pkg);
            if (!p) { printf("ERR not running\n"); continue; }
            if (g_mem >= 0) close(g_mem);
            char mp[64];
            snprintf(mp, sizeof mp, "/proc/%d/mem", p);
            g_mem = open(mp, O_RDWR);
            if (g_mem < 0) { printf("ERR open mem: %s\n", strerror(errno)); continue; }
            g_pid = p;
            g_count = 0;
            pthread_mutex_lock(&g_lock);
            g_nfrz = 0;
            pthread_mutex_unlock(&g_lock);
            printf("OK %d\n", p);
            continue;
        }

        if (!strcmp(cmd, "maps")) { cmd_maps(); continue; }

        if (!strcmp(cmd, "scan1")) {
            int t;
            unsigned long long v;
            if (sscanf(line, "%*s %d %llu", &t, &v) != 2 || t < 0 || t > 5) { printf("ERR usage\n"); continue; }
            cmd_scan1(t, (uint64_t)v);
            continue;
        }

        if (!strcmp(cmd, "next")) {
            int t, pred;
            unsigned long long v;
            if (sscanf(line, "%*s %d %d %llu", &t, &pred, &v) != 3 || t < 0 || t > 5 || pred < 0 || pred > 7) { printf("ERR usage\n"); continue; }
            cmd_next(t, pred, (uint64_t)v);
            continue;
        }

        if (!strcmp(cmd, "results")) {
            unsigned long long s, n;
            int t;
            if (sscanf(line, "%*s %llu %llu %d", &s, &n, &t) != 3 || t < 0 || t > 5) { printf("ERR usage\nEND\n"); continue; }
            cmd_results((uint64_t)s, (uint64_t)n, t);
            continue;
        }

        if (!strcmp(cmd, "write")) {
            unsigned long long a, v;
            int t;
            if (sscanf(line, "%*s %llx %d %llu", &a, &t, &v) != 3) { printf("ERR usage\n"); continue; }
            cmd_write((uint64_t)a, t, (uint64_t)v);
            continue;
        }

        if (!strcmp(cmd, "freeze")) {
            unsigned long long a, v;
            int t;
            if (sscanf(line, "%*s %llx %d %llu", &a, &t, &v) != 3) { printf("ERR usage\n"); continue; }
            cmd_freeze((uint64_t)a, t, (uint64_t)v);
            continue;
        }

        if (!strcmp(cmd, "unfreeze")) {
            unsigned long long a;
            if (sscanf(line, "%*s %llx", &a) != 1) { printf("ERR usage\n"); continue; }
            cmd_unfreeze((uint64_t)a);
            continue;
        }

        if (!strcmp(cmd, "findstr") || !strcmp(cmd, "findaob")) {
            char *arg = strchr(line, ' ');
            if (!arg) { printf("ERR missing pattern\nEND\n"); continue; }
            while (*arg == ' ') arg++;
            arg[strcspn(arg, "\r\n")] = 0;
            cmd_pattern(arg, !strcmp(cmd, "findstr"));
            continue;
        }
        if (!strcmp(cmd, "ptr")) {
            unsigned long long a;
            if (sscanf(line, "%*s %llx", &a) != 1) { printf("ERR usage\n"); continue; }
            cmd_pointer((uint64_t)a); continue;
        }
        if (!strcmp(cmd, "ptrscan")) {
            unsigned long long a;
            if (sscanf(line, "%*s %llx", &a) != 1) { printf("ERR usage\nEND\n"); continue; }
            cmd_ptrscan((uint64_t)a); continue;
        }
        if (!strcmp(cmd, "readhex")) {
            unsigned long long a; unsigned int n;
            if (sscanf(line, "%*s %llx %u", &a, &n) != 2) { printf("ERR usage\n"); continue; }
            cmd_readhex((uint64_t)a, (size_t)n); continue;
        }
        if (!strcmp(cmd, "writehex")) {
            unsigned long long a; char hex[129];
            if (sscanf(line, "%*s %llx %128s", &a, hex) != 2) { printf("ERR usage\n"); continue; }
            cmd_writehex((uint64_t)a, hex); continue;
        }

        if (!strcmp(cmd, "count")) { printf("OK %llu\n", (unsigned long long)g_count); continue; }

        if (!strcmp(cmd, "clear")) {
            g_count = 0;
            unlink(SCANFILE);
            printf("OK\n");
            continue;
        }

        printf("ERR unknown\n");
    }
    return 0;
}

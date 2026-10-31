/*
 * harness.c - batch driver shared by every fuzz target.
 *
 *     harness BATCH_FILE [COV_OUT]
 *
 * BATCH_FILE is a sequence of records, each a little-endian u32 length
 * followed by that many bytes. Each record is handed to fuzz_target() in
 * turn, preceded by a call to fuzz_input_begin(id).
 *
 * fuzz_input_begin exists to be traced. Kvasir records its ENTER with the
 * `fuzz_id` parameter, and that sample is how the Python side attributes the
 * samples that follow it to the input that produced them. It must therefore
 * stay a real, non-inlined, externally visible function.
 *
 * In the coverage build (compiled with -DFUZZ_COV and linked with cov.c),
 * COV_OUT receives one text line per record, written and flushed BEFORE the
 * next record starts:
 *
 *     S <id>                      record <id> is about to run
 *     F <id> <feature>...         coverage features it reached
 *     C <id> <constant>...        constants it was compared against
 *
 * The `S` line is flushed first, so when an input crashes the process the
 * last `S` without a matching `F` names the input that did it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef FUZZ_SAN
#include <setjmp.h>
#include <signal.h>

/* The sanitizer build survives fatal signals, so a SIGFPE (division by zero)
 * or SIGSEGV costs one report, not a restart of the sanitized process.
 * ASan/UBSan are built and run in recover mode, and told to leave these
 * signals to us (scripts/fuzzloop/runner.py, SAN_ENV). Forking per input was
 * measured instead and cost 2.2ms per input under ASan. */
static sigjmp_buf fuzz_jmp;

static void fuzz_on_signal(int sig) { siglongjmp(fuzz_jmp, sig); }

#define FUZZ_ABANDONED 1000

#ifdef FUZZ_ORACLE
/* Called by FUZZ_BUG_FATAL: skip the rest of this input, report nothing. */
void fuzz_oracle_abandon(void) { siglongjmp(fuzz_jmp, FUZZ_ABANDONED); }

/* Called by FUZZ_MARK (seeded faults): report, then carry on. */
int fuzz_mark(const char *id, const char *fn) {
    fprintf(stderr, "@@BUG %s %s\n", id, fn);
    return 0;
}
#endif

static void fuzz_catch_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fuzz_on_signal;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);   /* e.g. a stack-protector failure */
}
#endif

#include "fuzz.h"

#ifdef FUZZ_COV
void fuzz_cov_reset(void);
void fuzz_cov_dump(FILE *out, unsigned id);
#endif

__attribute__((noinline)) void fuzz_input_begin(int fuzz_id) {
    /* Keeps the call from being discarded; the parameter is what matters. */
    __asm__ volatile("" : : "r"(fuzz_id) : "memory");
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    size_t cap = 1 << 16, n = 0;
    uint8_t *buf = malloc(cap);
    size_t got;
    while (buf && (got = fread(buf + n, 1, cap - n, f)) > 0) {
        n += got;
        if (n == cap)
            buf = realloc(buf, cap *= 2);
    }
    fclose(f);
    *len = n;
    return buf;
}

/* Where the batch run is: the record now running. In fork-server mode it
 * lives in memory shared with the parent, which reads it when a child dies. */
struct fuzz_progress {
    size_t pos;          /* offset of the current record's length field */
    unsigned id;         /* its id */
    int running;         /* 1 between a record's start and its end */
};

static void run_records(const uint8_t *batch, size_t len, struct fuzz_progress *pr
#ifdef FUZZ_COV
                        , FILE *cov
#endif
                        ) {
    /* volatile: both change after sigsetjmp and are read after a longjmp. */
    volatile size_t pos = pr->pos;
    volatile unsigned id = pr->id;
    while (pos + 4 <= len) {
        uint32_t n = (uint32_t)batch[pos] | (uint32_t)batch[pos + 1] << 8 |
                     (uint32_t)batch[pos + 2] << 16 |
                     (uint32_t)batch[pos + 3] << 24;
        pr->pos = pos;
        pr->id = id;
        pr->running = 1;
        pos += 4;
        if (n > len - pos)
            n = (uint32_t)(len - pos);
#ifdef FUZZ_COV
        if (cov) {
            fprintf(cov, "S %u\n", id);
            fflush(cov);
        }
        fuzz_cov_reset();
#endif
        /* Each record gets an allocation of exactly its own size. Kvasir
         * sizes a pointee by its heap block, so handing out a pointer into
         * the batch buffer would make every traced pointer to the input
         * dump the REST OF THE BATCH - quadratic trace size, measured at
         * 110 MB for 1000 inputs. */
#ifdef FUZZ_SAN
        /* The sanitizer build: everything ASan/UBSan print after this line
         * belongs to this record (scripts/fuzzloop/bugs.py). */
        fprintf(stderr, "@@FUZZ-INPUT %u\n", id);
        fflush(stderr);
#endif
#ifdef FUZZ_SAN
        int sig = sigsetjmp(fuzz_jmp, 1);
        if (sig) {
            if (sig != FUZZ_ABANDONED)
                fprintf(stderr, "@@FUZZ-DIED %u %d\n", id, sig);
            pos += n;
            id++;
            pr->running = 0;
            continue;
        }
#endif
        uint8_t *rec = malloc(n ? n : 1);
        memcpy(rec, batch + pos, n);
        fuzz_input_begin((int)id);
        fuzz_target(rec, n);
        free(rec);
#ifdef FUZZ_COV
        if (cov)
            fuzz_cov_dump(cov, id);
#endif
        pos += n;
        id++;
        pr->running = 0;
    }
    pr->pos = pos;
    pr->id = id;
}

/* Fork-server mode (FUZZ_FORK=1 in the environment; the native and
 * sanitizer runs use it, Kvasir never does). A record that kills the
 * process used to cost a restart: exec, ASan start-up, re-reading the batch,
 * about 0.1 s, and replace's inputs do it hundreds of times per round. Here
 * a child runs the batch; when it dies, the parent notes the record it died
 * in and forks a fresh child from the next one, for about 1 ms. */
static int fork_server(const uint8_t *batch, size_t len
#ifdef FUZZ_COV
                       , FILE *cov
#endif
                       ) {
    struct fuzz_progress *pr = mmap(NULL, sizeof *pr, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (pr == MAP_FAILED)
        return -1;
    memset(pr, 0, sizeof *pr);
    for (;;) {
        fflush(NULL);                  /* nothing buffered twice */
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0) {
            run_records(batch, len, pr
#ifdef FUZZ_COV
                        , cov
#endif
                        );
            fflush(NULL);
            _exit(0);
        }
        int st;
        if (waitpid(pid, &st, 0) < 0)
            return -1;
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0 && !pr->running)
            return 0;
        if (!pr->running)
            return 1;                  /* died between records: give up */
        /* The child died inside record pr->id. */
        int code = WIFSIGNALED(st) ? WTERMSIG(st) : 1000 + WEXITSTATUS(st);
#ifdef FUZZ_COV
        if (cov) {
            fprintf(cov, "X %u %d\n", pr->id, code);
            fflush(cov);
        }
#endif
#ifdef FUZZ_SAN
        /* A sanitizer that exits after its report has already said what
         * happened; a signal has not. */
        if (WIFSIGNALED(st))
            fprintf(stderr, "@@FUZZ-DIED %u %d\n", pr->id, code);
#endif
        uint32_t n = (uint32_t)batch[pr->pos] | (uint32_t)batch[pr->pos + 1] << 8 |
                     (uint32_t)batch[pr->pos + 2] << 16 |
                     (uint32_t)batch[pr->pos + 3] << 24;
        size_t next = pr->pos + 4 + (n > len - pr->pos - 4 ? len - pr->pos - 4 : n);
        pr->pos = next;
        pr->id++;
        pr->running = 0;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s BATCH_FILE [COV_OUT]\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    uint8_t *batch = read_file(argv[1], &len);
    if (!batch) {
        perror(argv[1]);
        return 2;
    }
#ifdef FUZZ_COV
    FILE *cov = argc > 2 ? fopen(argv[2], "w") : NULL;
#endif

#ifdef FUZZ_SAN
    fuzz_catch_signals();
#endif
    int rc = 0;
    const char *fork_env = getenv("FUZZ_FORK");
    if (fork_env && *fork_env == '1') {
        rc = fork_server(batch, len
#ifdef FUZZ_COV
                         , cov
#endif
                         );
    } else {
        struct fuzz_progress pr = {0, 0, 0};
        run_records(batch, len, &pr
#ifdef FUZZ_COV
                    , cov
#endif
                    );
    }
#ifdef FUZZ_COV
    if (cov)
        fclose(cov);
#endif
    free(batch);
    return rc < 0 ? 3 : rc;
}

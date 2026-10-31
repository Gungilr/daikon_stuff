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

/* The batch and the loop state live in static memory, never on the stack.
 * Juliet's stack-overflow cases write past a stack array at an index the
 * input chooses; in the Kvasir and coverage builds nothing stops them, and
 * stack-held loop counters just above fuzz_target's frame got overwritten:
 * `pos` jumped backwards and the batch replayed with ever-growing ids
 * (80,201 inputs traced for a batch of 908). Statics also survive the
 * sanitizer build's siglongjmp without needing `volatile` locals.
 *
 * Kvasir writes every global at every sample until the loop's var list is
 * in place, and follows pointers: a `const uint8_t *` batch pointer dumped
 * the whole batch at each program point. So the one static is the address
 * of the state as an integer, which Kvasir prints as a number. */
struct fuzz_state {
    const uint8_t *batch;
    size_t len;
    struct fuzz_progress *pr;
#ifdef FUZZ_COV
    FILE *cov;
#endif
};
static uintptr_t fuzz_state_addr;
#define FS ((struct fuzz_state *)fuzz_state_addr)
#define fuzz_batch (FS->batch)
#define fuzz_len (FS->len)
#define fuzz_pr (FS->pr)
#ifdef FUZZ_COV
#define fuzz_cov (FS->cov)
#endif

/* Abort the batch if the target scribbled on the loop state anyway (a
 * global overflow can reach static memory). Exit code 86 reads as a crash
 * in the record that was running, which is the right one to blame. */
static void fuzz_check(size_t pos, size_t expect) {
    if (pos != expect || pos > fuzz_len) {
        fprintf(stderr, "harness: loop state corrupted by the target\n");
        _exit(86);
    }
}

static uint32_t record_len(size_t pos) {
    const uint8_t *b = fuzz_batch + pos;
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 |
           (uint32_t)b[3] << 24;
}

/* Offset of the record after the one at pos. */
static size_t next_record(size_t pos) {
    uint32_t n = record_len(pos);
    if (n > fuzz_len - pos - 4)
        n = (uint32_t)(fuzz_len - pos - 4);
    return pos + 4 + n;
}

static void run_records(void) {
    struct fuzz_progress *pr = fuzz_pr;
    while (pr->pos + 4 <= fuzz_len) {
        size_t start = pr->pos;
        uint32_t n = record_len(start);
        if (n > fuzz_len - start - 4)
            n = (uint32_t)(fuzz_len - start - 4);
        pr->running = 1;
#ifdef FUZZ_COV
        if (fuzz_cov) {
            fprintf(fuzz_cov, "S %u\n", pr->id);
            fflush(fuzz_cov);
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
        fprintf(stderr, "@@FUZZ-INPUT %u\n", pr->id);
        fflush(stderr);
        int sig = sigsetjmp(fuzz_jmp, 1);
        if (sig) {
            pr = fuzz_pr;
            if (sig != FUZZ_ABANDONED)
                fprintf(stderr, "@@FUZZ-DIED %u %d\n", pr->id, sig);
            fuzz_check(pr->pos, start);
            pr->pos = next_record(pr->pos);
            pr->id++;
            pr->running = 0;
            continue;
        }
#endif
        uint8_t *rec = malloc(n ? n : 1);
        memcpy(rec, fuzz_batch + start + 4, n);
        fuzz_input_begin((int)pr->id);
        fuzz_target(rec, n);
        free(rec);
        pr = fuzz_pr;
        fuzz_check(pr->pos, start);
#ifdef FUZZ_COV
        if (fuzz_cov)
            fuzz_cov_dump(fuzz_cov, pr->id);
#endif
        pr->pos = next_record(pr->pos);
        pr->id++;
        pr->running = 0;
    }
}

/* Fork-server mode (FUZZ_FORK=1 in the environment; the native and
 * sanitizer runs use it, Kvasir never does). A record that kills the
 * process used to cost a restart: exec, ASan start-up, re-reading the batch,
 * about 0.1 s, and replace's inputs do it hundreds of times per round. Here
 * a child runs the batch; when it dies, the parent notes the record it died
 * in and forks a fresh child from the next one, for about 1 ms. */
static int fork_server(void) {
    struct fuzz_progress *pr = mmap(NULL, sizeof *pr, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (pr == MAP_FAILED)
        return -1;
    memset(pr, 0, sizeof *pr);
    fuzz_pr = pr;
    for (;;) {
        fflush(NULL);                  /* nothing buffered twice */
        pid_t pid = fork();
        if (pid < 0)
            return -1;
        if (pid == 0) {
            run_records();
            fflush(NULL);
            _exit(0);
        }
        int st;
        if (waitpid(pid, &st, 0) < 0)
            return -1;
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0 && !pr->running)
            return 0;
        if (!pr->running || pr->pos + 4 > fuzz_len)
            return 1;                  /* died between records: give up */
        /* The child died inside record pr->id. */
        int code = WIFSIGNALED(st) ? WTERMSIG(st) : 1000 + WEXITSTATUS(st);
#ifdef FUZZ_COV
        if (fuzz_cov) {
            fprintf(fuzz_cov, "X %u %d\n", pr->id, code);
            fflush(fuzz_cov);
        }
#endif
#ifdef FUZZ_SAN
        /* A sanitizer that exits after its report has already said what
         * happened; a signal has not. */
        if (WIFSIGNALED(st))
            fprintf(stderr, "@@FUZZ-DIED %u %d\n", pr->id, code);
#endif
        pr->pos = next_record(pr->pos);
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
    /* On the heap: a static here would be one more global for Kvasir. */
    fuzz_state_addr = (uintptr_t)calloc(1, sizeof(struct fuzz_state));
#ifdef FUZZ_COV
    fuzz_cov = argc > 2 ? fopen(argv[2], "w") : NULL;
#endif
    fuzz_batch = batch;
    fuzz_len = len;

#ifdef FUZZ_SAN
    fuzz_catch_signals();
#endif
    int rc = 0;
    const char *fork_env = getenv("FUZZ_FORK");
    if (fork_env && *fork_env == '1') {
        rc = fork_server();
    } else {
        fuzz_pr = calloc(1, sizeof(struct fuzz_progress));
        run_records();
    }
#ifdef FUZZ_COV
    if (fuzz_cov)
        fclose(fuzz_cov);
#endif
    free(batch);
    return rc < 0 ? 3 : rc;
}

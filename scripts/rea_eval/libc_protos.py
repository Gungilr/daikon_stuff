"""Argument / return classes of common libc functions, used as type evidence.

Classes:  p pointer   s char*   F FILE*   f function pointer
          i int (signed)   u unsigned / size_t   l long (signed 64)   d double   v void
A trailing '...' means variadic: classes after the fixed arguments are unknown.
"""

PROTOS = {
    # memory
    "malloc": ("p", "u"), "calloc": ("p", "uu"), "realloc": ("p", "pu"), "free": ("v", "p"),
    "memcpy": ("p", "ppu"), "memmove": ("p", "ppu"), "memset": ("p", "piu"),
    "memcmp": ("i", "ppu"), "memchr": ("p", "piu"),
    # strings
    "strlen": ("u", "s"), "strnlen": ("u", "su"), "strcmp": ("i", "ss"), "strncmp": ("i", "ssu"),
    "strcasecmp": ("i", "ss"), "strncasecmp": ("i", "ssu"), "strcpy": ("s", "ss"),
    "strncpy": ("s", "ssu"), "strcat": ("s", "ss"), "strncat": ("s", "ssu"), "strchr": ("s", "si"),
    "strrchr": ("s", "si"), "strstr": ("s", "ss"), "strdup": ("s", "s"), "strndup": ("s", "su"),
    "strtok": ("s", "ss"), "strtok_r": ("s", "ssp"), "strspn": ("u", "ss"), "strcspn": ("u", "ss"),
    "strpbrk": ("s", "ss"), "strerror": ("s", "i"),
    "atoi": ("i", "s"), "atol": ("l", "s"), "atof": ("d", "s"), "strtol": ("l", "spi"),
    "strtoul": ("u", "spi"), "strtoll": ("l", "spi"), "strtoull": ("u", "spi"), "strtod": ("d", "sp"),
    "toupper": ("i", "i"), "tolower": ("i", "i"), "isspace": ("i", "i"), "isdigit": ("i", "i"),
    "isalpha": ("i", "i"), "isalnum": ("i", "i"), "isprint": ("i", "i"), "isxdigit": ("i", "i"),
    # stdio
    "printf": ("i", "s..."), "fprintf": ("i", "Fs..."), "sprintf": ("i", "ss..."),
    "snprintf": ("i", "sus..."), "vfprintf": ("i", "Fsp"), "vsnprintf": ("i", "susp"),
    "puts": ("i", "s"), "fputs": ("i", "sF"), "putchar": ("i", "i"), "fputc": ("i", "iF"),
    "putc": ("i", "iF"), "fgetc": ("i", "F"), "getc": ("i", "F"), "fgets": ("s", "siF"),
    "fopen": ("F", "ss"), "fdopen": ("F", "is"), "fclose": ("i", "F"), "fflush": ("i", "F"),
    "fread": ("u", "puuF"), "fwrite": ("u", "puuF"), "fseek": ("i", "Fli"), "ftell": ("l", "F"),
    "rewind": ("v", "F"), "feof": ("i", "F"), "ferror": ("i", "F"), "fileno": ("i", "F"),
    "sscanf": ("i", "ss..."), "fscanf": ("i", "Fs..."), "scanf": ("i", "s..."),
    "perror": ("v", "s"), "getline": ("l", "ppF"), "setvbuf": ("i", "Fsiu"),
    # posix / io
    "open": ("i", "si..."), "close": ("i", "i"), "read": ("l", "ipu"), "write": ("l", "ipu"),
    "lseek": ("l", "ili"), "stat": ("i", "sp"), "fstat": ("i", "ip"), "unlink": ("i", "s"),
    "access": ("i", "si"), "mkdir": ("i", "su"), "opendir": ("p", "s"), "readdir": ("p", "p"),
    "closedir": ("i", "p"), "getenv": ("s", "s"), "setenv": ("i", "ssi"), "system": ("i", "s"),
    "exit": ("v", "i"), "_exit": ("v", "i"), "abort": ("v", ""), "atexit": ("i", "f"),
    "sleep": ("u", "u"), "usleep": ("i", "u"), "time": ("l", "p"), "clock": ("l", ""),
    "gettimeofday": ("i", "pp"), "clock_gettime": ("i", "ip"), "localtime": ("p", "p"),
    "strftime": ("u", "susp"), "socket": ("i", "iii"), "bind": ("i", "ipu"), "listen": ("i", "ii"),
    "accept": ("i", "ipp"), "connect": ("i", "ipu"), "send": ("l", "ipui"), "recv": ("l", "ipui"),
    "select": ("i", "ipppp"), "poll": ("i", "pui"), "ioctl": ("i", "iu..."), "signal": ("f", "if"),
    "pthread_create": ("i", "ppfp"), "pthread_join": ("i", "up"), "pthread_mutex_lock": ("i", "p"),
    "pthread_mutex_unlock": ("i", "p"), "getopt": ("i", "ips"), "getopt_long": ("i", "ipspp"),
    # misc
    "qsort": ("v", "puuf"), "bsearch": ("p", "ppuuf"), "rand": ("i", ""), "srand": ("v", "u"),
    "abs": ("i", "i"), "labs": ("l", "l"),
    "sqrt": ("d", "d"), "pow": ("d", "dd"), "sin": ("d", "d"), "cos": ("d", "d"), "tan": ("d", "d"),
    "atan2": ("d", "dd"), "exp": ("d", "d"), "log": ("d", "d"), "log10": ("d", "d"),
    "floor": ("d", "d"), "ceil": ("d", "d"), "fabs": ("d", "d"), "fmod": ("d", "dd"),
    "round": ("d", "d"),
}


def lookup(name):
    """'<EXTERNAL>::memcmp' or 'memcmp' -> (ret_class, [arg classes], variadic)."""
    if not name:
        return None
    base = name.split("::")[-1]
    p = PROTOS.get(base)
    if p is None:
        return None
    ret, args = p
    variadic = args.endswith("...")
    return ret, list(args.replace("...", "")), variadic


POINTER_CLASSES = set("psFf")

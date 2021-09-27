#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SHSTASH_DEFAULT_SHELL
#define SHSTASH_DEFAULT_SHELL "/bin/sh"
#endif

#ifndef SHSTASH_DEFAULT_ROOT
#define SHSTASH_DEFAULT_ROOT "/var/tmp"
#endif

#ifndef SHSTASH_BASENAME_TEMPLATE
#define SHSTASH_BASENAME_TEMPLATE "shstash-XXXXXXXX"
#endif

#ifndef SHSTASH_PATH_LEN_MAX
#define SHSTASH_PATH_LEN_MAX PATH_MAX
#endif

typedef struct {
  const char *       dir_path;
  const char *const *argv;
} shell_T;

static void vperr(int errnum, const char *fmt, va_list ap);
static void perr(int errnum, const char *fmt, ...);
static void vdie(const char *fmt, va_list ap);
static void die(const char *fmt, ...);
static void vdie_errnum(int errnum, const char *fmt, va_list ap);
static void die_errnum(int errnum, const char *fmt, ...);

static const char *getenv_nonempty(const char *name);
static void        path_join2(char *buf, size_t sz,                   //
                              const char *dirname, size_t sz_dirname, //
                              const char *name, size_t sz_name);      //
static void        path_resolve(char *restrict buf, size_t sz_buf,    //
                                const char *restrict name);

static const char *divine_root(void);
static void        divine_shell(char *buf, size_t sz_buf);

static void mk_tempdir(char *bufpath, size_t sz);
static void rm_tempdir(const char *path);

static void handle_signal_dummy(int signo);
static void sigset_add(sigset_t *set, int sigs[], size_t sz);
static void sigprocmask_block_by_sigset(sigset_t *set);
static void sigprocmask_overwrite_by_sigset(sigset_t *set);
static void sigprocmask_block(int sigs[], size_t sz);
static void sigprocmask_overwrite(int sigs[], size_t sz);
static void sigprocmask_zero(void);

static int wait_child(pid_t child_pid);
static int run_shell(const shell_T *shell);

void
vperr(int errnum, const char *fmt, va_list ap) {
  fprintf(stderr, "shstash: ");
  vfprintf(stderr, fmt, ap);

  if (fmt[0] && fmt[strlen(fmt) - 1] == ':') {
    const char *errstr = strerror(errnum);
    if (errstr == (char *)EINVAL) {
      fprintf(stderr, " unknown error: %d\n", errnum);
    } else {
      fprintf(stderr, " %s\n", errstr);
    }
  } else {
    fputc('\n', stderr);
  }
}

void
perr(int errnum, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vperr(errnum, fmt, ap);
  va_end(ap);
}

void
vdie(const char *fmt, va_list ap) {
  vperr(errno, fmt, ap);
  exit(EXIT_FAILURE);
}

void
die(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vdie(fmt, ap);
  va_end(ap);
}

void
vdie_errnum(int errnum, const char *fmt, va_list ap) {
  vperr(errnum, fmt, ap);
  exit(EXIT_FAILURE);
}

void
die_errnum(int errnum, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vdie_errnum(errnum, fmt, ap);
  va_end(ap);
}

const char *
getenv_nonempty(const char *name) {
  const char *env = getenv(name);
  if (!env) return NULL;
  if (env && !strlen(env)) return NULL;
  return env;
}

void
path_join2(char *buf, size_t sz_buf,               //
           const char *dirname, size_t sz_dirname, //
           const char *name, size_t sz_name) {
  if (sz_buf < (sz_dirname + sz_name + //
                1 +                    // path separator
                1))                    // terminator
    die("path_join2: undersized buffer");
  memcpy(buf, dirname, sz_dirname);
  size_t n = sz_dirname;
  buf[n++] = '/';
  memcpy(buf + n, name, sz_name);
  n += sz_name;
  buf[n++] = '\0';
}

// execvp is not async-signal-safe so we do this ourselves.
void
path_resolve(char *restrict buf, size_t sz_buf, const char *restrict name) {
  char buft[SHSTASH_PATH_LEN_MAX];
  const char *restrict resolved;
  size_t lname = strlen(name);

  if (sz_buf < lname + 1) die("path_resolve: undersized buffer");
  for (int i = 0; i < lname; i++) {
    if (name[i] == '/') {
      resolved = name;
      goto done;
    }
  }

  const char *p = getenv_nonempty("PATH");
  if (sz_buf < strlen(p) + 1) die("path_resolve: undersized buffer");
  strcpy(buf, p);

  char *next, *last;
  next = strtok_r(buf, ":", &last);
  while (next) {
    path_join2(buft, sizeof(buft), //
               next, strlen(next), //
               name, lname);
    if (!access(buft, X_OK)) {
      resolved = buft;
      goto done;
    }
    next = strtok_r(NULL, ":", &last);
  }

  resolved = name; // ¯\_(ツ)_/¯

done:
  strcpy(buf, resolved);
}

const char *
divine_root(void) {
  const char *s;
  if ((s = getenv_nonempty("SHSTASH_ROOT"))) return s;
  return SHSTASH_DEFAULT_ROOT;
}

void
divine_shell(char *buf, size_t sz_buf) {
  const char *s = SHSTASH_DEFAULT_SHELL;
  const char *st;
  if ((st = getenv_nonempty("SHSTASH_SHELL"))) {
    s = st;
    goto resolve;
  }
  if ((st = getenv_nonempty("SHELL"))) {
    s = st;
    goto resolve;
  }
resolve:
  path_resolve(buf, sz_buf, s);
}

void
mk_tempdir(char *bufpath, size_t sz) {
  const char *root = divine_root();
  path_join2(bufpath, sz,        //
             root, strlen(root), //
             SHSTASH_BASENAME_TEMPLATE, strlen(SHSTASH_BASENAME_TEMPLATE));
  errno = 0;
  if (!mkdtemp(bufpath)) die("mkdtemp:");
}

void
rm_tempdir(const char *path) {
  DIR *dirp;
  errno = 0;
  dirp  = opendir(path);
  if (!dirp) {
    if (errno == ENOENT) return;
    die("opendir: %s:", path);
  }

  for (;;) {
    struct dirent *dirent;
    errno = 0;
    if (!(dirent = readdir(dirp))) {
      if (errno) die("readdir: %s", path);
      break;
    }

    const char *d_name = dirent->d_name;
    if (d_name[0] == '.') {
      if (d_name[1] == '\0') continue;
      if (d_name[1] == '.' && d_name[2] == '\0') continue;
    }

    char d_path[SHSTASH_PATH_LEN_MAX];
    path_join2(d_path, sizeof(d_path), //
               path, strlen(path),     //
               d_name, strlen(d_name));

    struct stat d_stat;
    errno = 0;
    if (lstat(d_path, &d_stat)) die("lstat: %s:", d_path);
    if (d_stat.st_mode & S_IFDIR) {
      rm_tempdir(d_path);
      continue;
    }
    if (unlink(d_path)) die("unlink: %s:", d_path);
  }

  closedir(dirp);
  if (rmdir(path)) die("rmdir: %s:", path);
}

// Dummy handler used to change our disposition toward SIG_IGN'd signals.
void
handle_signal_dummy(int signo) {}

static void
sigset_add(sigset_t *set, int sigs[], size_t sz) {
  for (size_t i = 0; i < sz; i++) sigaddset(set, sigs[i]);
}

static void
sigprocmask_block_by_sigset(sigset_t *set) {
  errno = 0;
  if (sigprocmask(SIG_BLOCK, set, NULL)) die("sigprocmask:");
}

static void
sigprocmask_overwrite_by_sigset(sigset_t *set) {
  errno = 0;
  if (sigprocmask(SIG_SETMASK, set, NULL)) die("sigprocmask:");
}

static void
sigprocmask_block(int sigs[], size_t sz) {
  sigset_t mask;
  sigemptyset(&mask);
  sigset_add(&mask, sigs, sz);
  sigprocmask_block_by_sigset(&mask);
}

static void
sigprocmask_overwrite(int sigs[], size_t sz) {
  sigset_t mask;
  sigemptyset(&mask);
  sigset_add(&mask, sigs, sz);
  sigprocmask_overwrite_by_sigset(&mask);
}

static void
sigprocmask_zero(void) {
  sigprocmask_overwrite(NULL, 0);
}

int
wait_child(pid_t child_pid) {
  sigset_t mask;
  sigemptyset(&mask);
  sigset_add(&mask, (int[]){SIGCHLD, SIGINT, SIGQUIT, SIGTERM}, 4);
  sigprocmask_block_by_sigset(&mask);

  errno = 0;
  if (sigaction(SIGCHLD, // SIG_IGN'd by default
                &(const struct sigaction){
                    .sa_handler = handle_signal_dummy,
                    .sa_flags   = SA_NOCLDSTOP,
                },
                NULL))
    die("sigaction:");

  int rc = 0;
  for (;;) {
    int errnum, sig;
    if ((errnum = sigwait(&mask, &sig))) die_errnum(errnum, "sigwait:");

    int status;
    switch (sig) {
    case SIGCHLD:
      if (waitpid(child_pid, &status, 0) == -1) die("wait:");
      if (WIFEXITED(status)) rc = WEXITSTATUS(status);
      if (WIFSIGNALED(status)) rc = 128 + WTERMSIG(status);
      goto done;
    case SIGQUIT:
      if (kill(child_pid, SIGKILL)) die("kill:");
      break;
    default:
      if (kill(child_pid, SIGTERM)) die("kill:");
    }
  }
done:
  return rc;
}

int
run_shell(const shell_T *shell) {
  int pwd;
  errno = 0;
  if ((pwd = open(".", O_RDONLY)) == -1) die("open .:");

  errno = 0;
  if (chdir(shell->dir_path)) die("chdir: %s:", shell->dir_path);

  pid_t pid;
  int   rc;
  errno = 0;
  pid   = vfork();
  if (pid == -1) die("vfork:");
  if (pid == 0) {
    sigprocmask_zero();
    errno = 0;
    // execv is async-signal-safe in POSIX.1-2008
    execv(shell->argv[0], (char *const *)shell->argv);
    _exit(EXIT_FAILURE);
  }
  if (errno) { // from execv; child shares our address space
    perr(errno, "exec: %s:", shell->argv[0]);
    waitpid(pid, NULL, 0);
    rc = EXIT_FAILURE;
  } else {
    rc = wait_child(pid);
  }

  errno = 0;
  if (fchdir(pwd)) die("fchdir .:");
  close(pwd);

  return rc;
}

char buftmpdir[SHSTASH_PATH_LEN_MAX];
char bufshell[SHSTASH_PATH_LEN_MAX];

int
main(int argc, char *argv[]) {
  sigprocmask_block((int[]){SIGINT, SIGQUIT, SIGTERM}, 3);

  mk_tempdir(buftmpdir, sizeof(buftmpdir));

  divine_shell(bufshell, sizeof(bufshell));
  argv[0] = bufshell;
  int rc  = run_shell(&(const shell_T){
      .dir_path = buftmpdir,
      .argv     = (const char *const *)argv,
  });

  rm_tempdir(buftmpdir);
  exit(rc);
}

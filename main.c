#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "thirdparty/sds/sds.h"

#ifndef SHSTASH_DEFAULT_SHELL
#define SHSTASH_DEFAULT_SHELL "/bin/sh"
#endif

#ifndef SHSTASH_DEFAULT_ROOT
#define SHSTASH_DEFAULT_ROOT "/var/tmp"
#endif

#ifndef SHSTASH_BASENAME_TEMPLATE
#define SHSTASH_BASENAME_TEMPLATE "shstash-XXXXXXXX"
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
void               path_resolve(sds *restrict p, const char *restrict name);

static void divine_root(sds *p);
static void divine_shell(sds *p);

static void mk_tempdir(sds *p);
static void rm_rf(const char *p);

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

// execvp is not async-signal-safe so we do this ourselves.
void
path_resolve(sds *restrict p, const char *restrict name) {
  size_t lname = strlen(name);
  for (int i = 0; i < lname; i++) {
    if (name[i] == '/') {
      sdsclear(*p);
      *p = sdscat(*p, name);
      return;
    }
  }

  const char *env = getenv_nonempty("PATH");

  int  npaths;
  sds *paths;
  paths = sdssplitlen(env, strlen(env), ":", 1, &npaths);
  for (int i = 0; i < npaths; i++) {
    sdsclear(*p);
    *p = sdscatsds(*p, paths[i]);
    *p = sdscat(*p, "/");
    *p = sdscat(*p, name);
    if (access(*p, X_OK)) continue;
    sdsfreesplitres(paths, npaths);
    return;
  }
  sdsfreesplitres(paths, npaths);

  sdsclear(*p);
  *p = sdscat(*p, name); // ¯\_(ツ)_/¯
}

void
divine_root(sds *p) {
  const char *s = SHSTASH_DEFAULT_ROOT, *t;
  if ((t = getenv_nonempty("SHSTASH_ROOT"))) s = t;
  sdsclear(*p);
  *p = sdscat(*p, s);
}

void
divine_shell(sds *p) {
  const char *s = SHSTASH_DEFAULT_SHELL, *t;
  if ((t = getenv_nonempty("SHSTASH_SHELL"))) {
    s = t;
    goto resolve;
  }
  if ((t = getenv_nonempty("SHELL"))) {
    s = t;
    goto resolve;
  }
resolve:
  path_resolve(p, s);
}

void
mk_tempdir(sds *p) {
  divine_root(p);
  *p    = sdscat(*p, "/" SHSTASH_BASENAME_TEMPLATE);
  errno = 0;
  if (!mkdtemp(*p)) die("mkdtemp:");
}

void
rm_rf_in(sds *p) {
  size_t lp = sdslen(*p);

  DIR *d;
  errno = 0;
  d     = opendir(*p);
  if (!d) {
    if (errno == ENOENT) return;
    die("opendir: %s:", *p);
  }

  for (;;) {
    sdsrange(*p, 0, lp);

    struct dirent *de;
    errno = 0;
    if (!(de = readdir(d))) {
      if (errno) die("readdir: %s", *p);
      break;
    }

    const char *dn = de->d_name;
    if (dn[0] == '.') {
      if (dn[1] == '\0') continue;
      if (dn[1] == '.' && dn[2] == '\0') continue;
    }
    *p = sdscat(*p, "/");
    *p = sdscat(*p, dn);

    struct stat ds;
    errno = 0;
    if (lstat(*p, &ds)) die("lstat: %s:", *p);
    if (!(ds.st_mode & S_IFDIR)) {
      if (unlink(*p)) die("unlink: %s:", *p);
      continue;
    }
    rm_rf_in(p);
  }

  closedir(d);
  sdsrange(*p, 0, lp);
  if (rmdir(*p)) die("rmdir: %s:", *p);
}

void
rm_rf(const char *p) {
  sds sp = sdsnewcap(2 * strlen(p));
  sp     = sdscat(sp, p);
  rm_rf_in(&sp);
  sdsfree(sp);
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

int
main(int argc, char *argv[]) {
  sigprocmask_block((int[]){SIGINT, SIGQUIT, SIGTERM}, 3);

  sds tempdir = sdsnewcap(127);
  mk_tempdir(&tempdir);

  sds shell = sdsnewcap(127);
  divine_shell(&shell);
  argv[0] = shell;
  int rc  = run_shell(&(const shell_T){
      .dir_path = tempdir,
      .argv     = (const char *const *)argv,
  });

  rm_rf(tempdir);
  exit(rc);
}

#include <dirent.h>
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
#define SHSTASH_PATH_LEN_MAX 256
#endif

typedef struct {
  const char *       dir_path;
  const char *const *argv;
} shell_T;

static void die(const char *fmt, ...);
static void die_errnum(int errnum, const char *fmt, ...);

static const char *divine_root(void);
static const char *divine_shell(void);
static const char *getenv_nonempty(const char *name);

static void path_join2(char *buf, size_t sz,                   //
                       const char *dirname, size_t sz_dirname, //
                       const char *name, size_t sz_name);      //
static void mk_tempdir(char *pathbuf, size_t sz);
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
die(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "shstash: ");
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  if (fmt[0] && fmt[strlen(fmt) - 1] == ':') {
    fputc(' ', stderr);
    perror(NULL);
  } else {
    fputc('\n', stderr);
  }
  exit(1);
}

void
die_errnum(int errnum, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "shstash: ");
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  if (fmt[0] && fmt[strlen(fmt) - 1] == ':') {
    const char *errstr = strerror(errnum);
    if ((int)errstr == EINVAL) {
      fprintf(stderr, " Unknown error: %d\n", errnum);
    } else {
      fprintf(stderr, " %s\n", errstr);
    }
  } else {
    fputc('\n', stderr);
  }
  exit(1);
}

const char *
getenv_nonempty(const char *name) {
  const char *env = getenv(name);
  if (!env) return NULL;
  if (env && !strlen(env)) return NULL;
  return env;
}

const char *
divine_root(void) {
  const char *s;
  if ((s = getenv_nonempty("SHSTASH_ROOT"))) return s;
  return SHSTASH_DEFAULT_ROOT;
}

const char *
divine_shell(void) {
  const char *s;
  if ((s = getenv_nonempty("SHSTASH_SHELL"))) return s;
  if ((s = getenv_nonempty("SHELL"))) return s;
  return SHSTASH_DEFAULT_SHELL;
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

void
mk_tempdir(char *pathbuf, size_t sz) {
  const char *root = divine_root();
  path_join2(pathbuf, sz,        //
             root, strlen(root), //
             SHSTASH_BASENAME_TEMPLATE, strlen(SHSTASH_BASENAME_TEMPLATE));
  errno = 0;
  if (!mkdtemp(pathbuf)) die("mkdtemp:");
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
  int rc = 0;

  pid_t pid;
  errno = 0;
  pid   = fork();

  if (pid == -1) die("fork:");
  if (pid == 0) {
    sigprocmask_zero();

    errno = 0;
    if (chdir(shell->dir_path)) die("chdir: %s:", shell->dir_path);

    errno = 0;
    execvp(shell->argv[0], (char *const *)shell->argv);
    die("exec: %s:", shell->argv[0]);
  } else {
    rc = wait_child(pid);
  }
  return rc;
}

int
main(int argc, char *argv[]) {
  sigprocmask_block((int[]){SIGINT, SIGQUIT, SIGTERM}, 3);

  char tempdir_buf[SHSTASH_PATH_LEN_MAX];
  mk_tempdir(tempdir_buf, sizeof(tempdir_buf));

  argv[0] = (char *)divine_shell();
  int rc  = run_shell(&(const shell_T){
      .dir_path = tempdir_buf,
      .argv     = (const char *const *)argv,
  });

  rm_tempdir(tempdir_buf);
  exit(rc);
}

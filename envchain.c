/* envchain
 *
 * Copyright (c) 2024 Sorah Fukumori
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <assert.h>
#include <errno.h>

#include <readline/readline.h>

#include "envchain.h"


static const char version[] = "1.1.0";
const char *envchain_name;

/* for help */

static void
envchain_abort_with_help(void)
{
  fprintf(
    stderr,
    "%s version %s\n\n"
    "Usage:\n"
    "  Global options\n"
    "    %s [--keychain PATH|--keychain-from-env|--keychain-dir DIR] ...\n"
    "\n"
    "  Add variables\n"
    "    %s (--set|-s) [--[no-]require-passphrase|-p|-P] [--noecho|-n] NAMESPACE ENV [ENV ..]\n"
    "  Change access policy without retyping value\n"
    "    %s --set-access [--require-passphrase|-p|--no-require-passphrase|-P] NAMESPACE ENV [ENV ..]\n"
    "  Execute with variables\n"
    "    %s NAMESPACE CMD [ARG ...]\n"
    "  List namespaces\n"
    "    %s --list\n"
    "  Remove variables\n"
    "    %s --unset NAMESPACE ENV [ENV ..]\n"
    "\n"
    "Options:\n"
    "  --keychain:\n"
    "    Use a specific macOS keychain file instead of default search list.\n"
    "\n"
    "  --keychain-from-env:\n"
    "    Read keychain path from ENVCHAIN_KEYCHAIN (disabled by default for safety).\n"
    "\n"
    "  --keychain-dir:\n"
    "    Auto-map namespace to DIR/<namespace>.keychain-db.\n"
    "    Equivalent env var: ENVCHAIN_KEYCHAIN_DIR.\n"
    "\n"
    "  --set (-s):\n"
    "    Add keychain item of environment variable +ENV+ for namespace +NAMESPACE+.\n"
    "\n"
    "  --set-access:\n"
    "    Update ACL policy of existing keys without modifying values.\n"
    "    Must provide either -p or -P.\n"
    "\n"
    "  --noecho (-n):\n"
    "    Enable noecho mode when prompting values. Requires stdin to be a terminal.\n"
    "\n"
    "  --require-passphrase (-p), --no-require-passphrase (-P):\n"
    "    Replace the item's ACL list to require passphrase (or not).\n"
    "    Leave as is when both options are omitted.\n"
    ,
    envchain_name, version, envchain_name, envchain_name, envchain_name, envchain_name, envchain_name, envchain_name
  );
  exit(2);
}

/* functions for --set */

char*
envchain_noecho_read(char* prompt)
{
  struct termios term, term_orig;
  char* str = NULL;
  ssize_t len;
  size_t n;

  if (tcgetattr(STDIN_FILENO, &term) < 0) {
    if (errno == ENOTTY) {
      fprintf(stderr, "--noecho (-n) requires stdin to be a terminal\n");
    }
    else {
      fprintf(stderr, "oops when attempted to read: %s\n", strerror(errno));
    }
    return NULL;
  }

  term_orig = term;
  term.c_lflag &= ~ECHO;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) < 0) {
    fprintf(stderr, "tcsetattr failed\n");
    exit(10);
  }

  printf("%s (noecho):", prompt);
  len = getline(&str, &n, stdin);

  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_orig) < 0) {
    fprintf(stderr, "tcsetattr restore failed\n");
    exit(10);
  }

  if (0 < len && str[len-1] == '\n')
    str[len - 1] = '\0';

  printf("\n");

  return str;
}


static char*
envchain_ask_value(const char* name, const char* key, int noecho)
{
  char *prompt, *line;
  asprintf(&prompt, "%s.%s", name, key);

  if (noecho) {
    line = envchain_noecho_read(prompt);
  }
  else {
    printf("%s", prompt);
    line = readline(": ");
  }

  free(prompt);
  return line;
}

int
envchain_set(int argc, const char **argv)
{
  int noecho = 0;
  int require_passphrase = -1;
  const char *name, *key;
  char *value;

  while (2 < argc) {
    if (argv[0][0] != '-') break;

    if (strcmp(argv[0], "-n") == 0 || strcmp(argv[0], "--noecho") == 0) {
      argv++; argc--;
      noecho = 1;
    }
    else if (strcmp(argv[0], "-p") == 0 || strcmp(argv[0], "--require-passphrase") == 0) {
      argv++; argc--;
      require_passphrase = 1;
    }
    else if (strcmp(argv[0], "-P") == 0 || strcmp(argv[0], "--no-require-passphrase") == 0) {
      argv++; argc--;
      require_passphrase = 0;
    }
    else {
      fprintf(stderr, "Unknown option: %s\n", argv[0]);
      return 1;
    }
  }
  if (argc < 2) envchain_abort_with_help();

  name = argv[0];
  argv++; argc--;

  while(0 < argc) {
    key = argv[0];
    argv++; argc--;

    value = envchain_ask_value(name, key, noecho);
    if (value == NULL) return 1;

    envchain_save_value(name, key, value, require_passphrase);
  }

  return 0;
}

/* functions for list */

static void
envchain_list_value_callback(const char *key, const char* value, void *raw_context)
{
  envchain_list_context* context = (envchain_list_context*)raw_context;

  if (context->show_value) {
    printf("%s=%s\n", key, value);
  }
  else {
    printf("%s\n", key);
  }
}

static void
envchain_list_namespace_callback(const char *name, void *raw_context)
{
  (void)raw_context; /* silence warning */

  printf("%s\n", name);
}

int
envchain_list(int argc, const char **argv)
{
  envchain_list_context context = {NULL,0};

  while (0 < argc) {
    if (strcmp(argv[0], "--show-value") == 0 || strcmp(argv[0], "-v") == 0) {
      argv++; argc--;
      context.show_value = 1;
    }
    else {
      if (context.target) envchain_abort_with_help();
      context.target = argv[0];
      argv++; argc--;
    }
  }

  if (context.target) {
    envchain_search_values(
      context.target, &envchain_list_value_callback, &context);
  }
  else {
    if (context.show_value) envchain_abort_with_help();

    envchain_search_namespaces(&envchain_list_namespace_callback, &context);
  }
  return 0;
}

/* functions for --unset */

int
envchain_unset(int argc, const char **argv)
{
  const char *name, *key;

  if (argc < 2) envchain_abort_with_help();

  name = argv[0];
  argv++; argc--;

  while (0 < argc) {
    key = argv[0];
    argv++; argc--;

    envchain_delete_value(name, key);
  }

  return 0;
}

/* functions for --set-access */

int
envchain_set_access(int argc, const char **argv)
{
  int require_passphrase = -1;
  const char *name, *key;
  int result = 0;

  while (2 < argc) {
    if (argv[0][0] != '-') break;

    if (strcmp(argv[0], "-p") == 0 || strcmp(argv[0], "--require-passphrase") == 0) {
      argv++; argc--;
      require_passphrase = 1;
    }
    else if (strcmp(argv[0], "-P") == 0 || strcmp(argv[0], "--no-require-passphrase") == 0) {
      argv++; argc--;
      require_passphrase = 0;
    }
    else {
      fprintf(stderr, "Unknown option: %s\n", argv[0]);
      return 1;
    }
  }
  if (argc < 2) envchain_abort_with_help();
  if (require_passphrase < 0) {
    fprintf(stderr, "--set-access requires either -p or -P\n");
    return 2;
  }

  name = argv[0];
  argv++; argc--;

  while(0 < argc) {
    key = argv[0];
    argv++; argc--;
    if (envchain_update_value_access(name, key, require_passphrase) != 0) {
      result = 1;
    }
  }

  return result;
}

/* functions for exec mode */

static void
envchain_exec_value_callback(const char* key, const char* value, void *context)
{
  (void)context; /* silence warning */

  setenv(key, value, 1);
}

int
envchain_exec(int argc, const char **argv)
{
  if (argc < 2) envchain_abort_with_help();

  char *name, *names, *exe;
  char **args;

  names = (char*)argv[0];
  exe = (char*)argv[1];
  argv++; argc--;
  argv++; argc--;

  while ((name = strsep(&names, ",")) != NULL) {
    envchain_search_values(name, &envchain_exec_value_callback, NULL);
  }

  int len = (2+argc);
  args = malloc(sizeof(char*) * len);
  args[0] = (char*)exe;
  args[len-1] = NULL;
  if (0 < argc) memcpy(args+1, argv, sizeof(char*) * argc);

  if (execvp(exe, args) < 0) {
    fprintf(stderr, "execvp failed: %s\n", strerror(errno));
    return 1;
  }
  return 0;
}

static char*
envchain_namespace_from_argv(int argc, const char **argv)
{
  const char *cmd;
  const char *ns = NULL;
  int i;

  if (argc < 1) return NULL;

  cmd = argv[0];
  if (strcmp(cmd, "--set") == 0 || strcmp(cmd, "-s") == 0 || strcmp(cmd, "--set-access") == 0) {
    i = 1;
    while (i < argc && argv[i][0] == '-') {
      i++;
    }
    if (i < argc) ns = argv[i];
  }
  else if (strcmp(cmd, "--unset") == 0) {
    if (1 < argc) ns = argv[1];
  }
  else if (strcmp(cmd, "--list") == 0 || strcmp(cmd, "-l") == 0) {
    i = 1;
    while (i < argc) {
      if (strcmp(argv[i], "--show-value") == 0 || strcmp(argv[i], "-v") == 0) {
        i++;
        continue;
      }
      ns = argv[i];
      break;
    }
  }
  else if (cmd[0] != '-') {
    /* exec mode: only auto-map when single namespace is specified */
    if (strchr(cmd, ',') == NULL) ns = cmd;
  }

  if (ns == NULL || ns[0] == '\0') return NULL;
  return strdup(ns);
}

static char*
envchain_build_namespace_keychain_path(const char *dir, const char *ns)
{
  char *path = NULL;
  asprintf(&path, "%s/%s.keychain-db", dir, ns);
  if (path == NULL) {
    fprintf(stderr, "Failed to generate keychain path\n");
    exit(10);
  }

  if (access(path, F_OK) != 0) {
    free(path);
    return NULL;
  }

  return path;
}

/* entry point */

int
main(int argc, const char **argv)
{
  int rc = 0;
  const char *keychain_target = NULL;
  const char *keychain_dir = NULL;
  int use_keychain_from_env = 0;
  char *auto_keychain_target = NULL;
  char *auto_namespace = NULL;

  envchain_name = argv[0];
  if (argc < 2) envchain_abort_with_help();
  argv++; argc--;

  while (0 < argc) {
    if (strcmp(argv[0], "--keychain") == 0) {
      argv++; argc--;
      if (argc < 1) {
        fprintf(stderr, "Missing argument for --keychain\n");
        rc = 2;
        goto cleanup;
      }
      keychain_target = argv[0];
      argv++; argc--;
    }
    else if (strcmp(argv[0], "--keychain-from-env") == 0) {
      use_keychain_from_env = 1;
      argv++; argc--;
    }
    else if (strcmp(argv[0], "--keychain-dir") == 0) {
      argv++; argc--;
      if (argc < 1) {
        fprintf(stderr, "Missing argument for --keychain-dir\n");
        rc = 2;
        goto cleanup;
      }
      keychain_dir = argv[0];
      argv++; argc--;
    }
    else {
      break;
    }
  }

  if (keychain_target == NULL && use_keychain_from_env) {
    keychain_target = getenv("ENVCHAIN_KEYCHAIN");
  }
  if (keychain_dir == NULL) {
    keychain_dir = getenv("ENVCHAIN_KEYCHAIN_DIR");
  }
  if (keychain_target == NULL && keychain_dir != NULL && keychain_dir[0] != '\0') {
    auto_namespace = envchain_namespace_from_argv(argc, argv);
    if (auto_namespace != NULL) {
      auto_keychain_target = envchain_build_namespace_keychain_path(keychain_dir, auto_namespace);
      if (auto_keychain_target != NULL) {
        keychain_target = auto_keychain_target;
      }
    }
  }

  if (envchain_set_keychain(keychain_target) != 0) {
    rc = 1;
    goto cleanup;
  }

  if (argc < 1) envchain_abort_with_help();

  if (strcmp(argv[0], "--set") == 0 || strcmp(argv[0], "-s") == 0) {
    argv++; argc--;
    rc = envchain_set(argc, argv);
    goto cleanup;
  }
  else if (strcmp(argv[0], "--list") == 0 || strcmp(argv[0], "-l") == 0) {
    argv++; argc--;
    rc = envchain_list(argc, argv);
    goto cleanup;
  }
  else if (strcmp(argv[0], "--unset") == 0) {
    argv++; argc--;
    rc = envchain_unset(argc, argv);
    goto cleanup;
  }
  else if (strcmp(argv[0], "--set-access") == 0) {
    argv++; argc--;
    rc = envchain_set_access(argc, argv);
    goto cleanup;
  }
  else if (argv[0][0] == '-') {
    fprintf(stderr, "Unknown option %s\n", argv[0]);
    rc = 2;
    goto cleanup;
  }
  else {
    rc = envchain_exec(argc, argv);
    goto cleanup;
  }

cleanup:
  if (auto_keychain_target != NULL) free(auto_keychain_target);
  if (auto_namespace != NULL) free(auto_namespace);
  return rc;
}

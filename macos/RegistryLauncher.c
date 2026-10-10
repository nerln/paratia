#include "AuthorizationBridge.h"
#include <mach-o/dyld.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The very same signed executable is the GUI and launchd entry point. Keep
 * this process alive: exec'ing Python would replace the app's TCC identity.
 * The daemon copy lives under a root-protected directory, not /Applications.
 */
extern void ParatiaRunGUI(void);
static volatile sig_atomic_t child_pid = 0;
static volatile sig_atomic_t pending_signal = 0;

static void forward_signal(int number) {
    pending_signal = number;
    if (child_pid > 0) kill((pid_t)child_pid, number);
}

static int protected_path(const char *path) {
    char current[PATH_MAX];
    if (strlen(path) >= sizeof(current)) return 0;
    strcpy(current, path);
    while (1) {
        if (ParatiaRootProtected(current) != 1) return 0;
        if (!strcmp(current, "/")) return 1;
        char *slash = strrchr(current, '/');
        if (!slash) return 0;
        if (slash == current) current[1] = '\0';
        else *slash = '\0';
    }
}

static int run_registry(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[2], "--uid") || geteuid() != 0) {
        fputs("Il registro richiede il servizio installato dal dialogo amministratore di Paratia.\n", stderr);
        return 2;
    }
    for (const char *p = argv[3]; *p; p++) if (*p < '0' || *p > '9') return 2;
    errno = 0;
    char *end = NULL;
    unsigned long uid = strtoul(argv[3], &end, 10);
    if (errno || !*argv[3] || *end || uid == 0 || uid > UINT_MAX) return 2;

    char own[PATH_MAX], canonical[PATH_MAX], python[PATH_MAX];
    uint32_t own_size = sizeof(own);
    const char *installed = "/Library/Application Support/Paratia/Paratia.app/Contents/MacOS/Paratia";
    const char *script = "/Library/Application Support/Paratia/registro_daemon.py";
    const char *python_prefix = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/";
    if (_NSGetExecutablePath(own, &own_size) || !realpath(own, canonical) ||
        strcmp(canonical, installed) || !protected_path(canonical) || !protected_path(script) ||
        !realpath("/Library/Developer/CommandLineTools/usr/bin/python3", python) ||
        strncmp(python, python_prefix, strlen(python_prefix)) ||
        !protected_path(python)) {
        fputs("La copia del servizio o il runtime Apple non è protetto. Reinstalla il registro da Paratia.\n", stderr);
        return 2;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = forward_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    char *arguments[] = {python, "-I", "-S", (char *)script, "--uid", argv[3], NULL};
    char *environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                          "PARATIA_REGISTRY_LAUNCHER=app", NULL};
    pid_t child;
    int error = posix_spawn(&child, python, NULL, NULL, arguments, environment);
    if (error) {
        fputs("Impossibile avviare il registro. Reinstalla i Command Line Tools e il servizio.\n", stderr);
        return 2;
    }
    child_pid = child;
    if (pending_signal) kill(child, pending_signal);
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 2;
    }
    child_pid = 0;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--registro")) return run_registry(argc, argv);
    ParatiaRunGUI();
    return 0;
}

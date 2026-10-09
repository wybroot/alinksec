#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int no_conversation(int count, const struct pam_message **messages,
                           struct pam_response **response, void *data) {
    (void)count; (void)messages; (void)response; (void)data;
    return PAM_CONV_ERR;
}
static void limit_json(const char *name, int resource) {
    struct rlimit value;
    if (getrlimit(resource, &value) != 0) exit(3);
    printf(",\"%s_soft\":\"", name);
    if (value.rlim_cur == RLIM_INFINITY) printf("unlimited");
    else printf("%llu", (unsigned long long)value.rlim_cur);
    printf("\",\"%s_hard\":\"", name);
    if (value.rlim_max == RLIM_INFINITY) printf("unlimited");
    else printf("%llu", (unsigned long long)value.rlim_max);
    printf("\"");
}
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "root") && strcmp(argv[1], "alinksec-pam-test"))) return 2;
    struct passwd *user = getpwnam(argv[1]);
    if (!user) return 2;
    uid_t uid = user->pw_uid; gid_t gid = user->pw_gid;
    struct pam_conv conversation = {no_conversation, NULL};
    pam_handle_t *handle = NULL;
    int rc = pam_start("login", argv[1], &conversation, &handle);
    if (rc == PAM_SUCCESS) rc = pam_open_session(handle, 0);
    printf("{\"rc\":%d", rc);
    limit_json("core", RLIMIT_CORE);
    limit_json("nofile", RLIMIT_NOFILE);
    limit_json("nproc", RLIMIT_NPROC);
    if (rc == PAM_SUCCESS && strcmp(argv[2], "enforce") == 0) {
        if (setgid(gid) || setuid(uid)) return 4;
        int files[96], count = 0, fd_errno = 0;
        for (; count < 96; count++) {
            files[count] = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (files[count] < 0) { fd_errno = errno; break; }
        }
        for (int i = 0; i < count; i++) close(files[i]);
        pid_t children[4]; int child_count = 0, fork_errno = 0;
        for (; child_count < 4; child_count++) {
            pid_t child = fork();
            if (child < 0) { fork_errno = errno; break; }
            if (child == 0) { pause(); _exit(0); }
            children[child_count] = child;
        }
        for (int i = 0; i < child_count; i++) {
            kill(children[i], SIGTERM);
            if (waitpid(children[i], NULL, 0) < 0) return 5;
        }
        printf(",\"fd_denied\":%s,\"fork_denied\":%s,\"children\":%d",
               fd_errno == EMFILE ? "true" : "false",
               fork_errno == EAGAIN ? "true" : "false", child_count);
    }
    printf("}\n");
    if (handle) pam_end(handle, rc);
    return 0;
}

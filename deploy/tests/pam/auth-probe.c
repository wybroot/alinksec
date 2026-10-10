#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct input { const char *user, *password; };
static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **out, void *data) {
    struct input *input = data;
    struct pam_response *responses = calloc((size_t)count, sizeof(*responses));
    if (!responses) return PAM_BUF_ERR;
    for (int i=0; i<count; i++) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF)
            responses[i].resp = strdup(input->password);
        else if (messages[i]->msg_style == PAM_PROMPT_ECHO_ON)
            responses[i].resp = strdup(input->user);
        else if (messages[i]->msg_style != PAM_TEXT_INFO && messages[i]->msg_style != PAM_ERROR_MSG) {
            for (int j=0; j<=i; j++) free(responses[j].resp);
            free(responses); return PAM_CONV_ERR;
        }
    }
    *out = responses; return PAM_SUCCESS;
}
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1],"root") && strcmp(argv[1],"alinksec-pam-test"))) return 2;
    char *password=NULL; size_t size=0;
    ssize_t length=getline(&password,&size,stdin);
    if (length<1 || length>512) return 2;
    password[strcspn(password,"\r\n")]=0;
    struct input input={argv[1],password}; struct pam_conv conv={conversation,&input};
    pam_handle_t *handle=NULL;
    int rc=pam_start("login",input.user,&conv,&handle);
    if (rc==PAM_SUCCESS) rc=pam_authenticate(handle,0);
    if (handle) pam_end(handle,rc);
    // No prompts, credentials or tally contents leave this disposable process.
    printf("rc=%d\n",rc);
    explicit_bzero(password,size);free(password);return 0;
}

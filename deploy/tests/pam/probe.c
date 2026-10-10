#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <crypt.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct tokens { const char *first, *second; int prompts; };
static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **out, void *data) {
    struct tokens *tokens = data;
    struct pam_response *responses = calloc((size_t)count, sizeof(*responses));
    if (!responses) return PAM_BUF_ERR;
    for (int i=0; i<count; i++) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            const char *value = tokens->prompts++ < 2 ? tokens->first : tokens->second;
            responses[i].resp = strdup(value);
        } else if (messages[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            responses[i].resp = strdup("root");
        } else if (messages[i]->msg_style != PAM_TEXT_INFO && messages[i]->msg_style != PAM_ERROR_MSG) {
            for (int j=0; j<=i; j++) free(responses[j].resp);
            free(responses); return PAM_CONV_ERR;
        }
    }
    *out = responses; return PAM_SUCCESS;
}
static int verifies(const char *token, const char *hash) {
    struct crypt_data *state = calloc(1,sizeof(*state));
    if (!state) return 0;
    char *value = crypt_r(token,hash,state);
    int matches = value && strcmp(value,hash)==0;
    explicit_bzero(state,sizeof(*state)); free(state); return matches;
}
int main(void) {
    char *first=NULL,*second=NULL; size_t a=0,b=0;
    ssize_t n=getline(&first,&a,stdin),m=getline(&second,&b,stdin);
    if (n<1 || m<1 || n>512 || m>512) return 2;
    first[strcspn(first,"\r\n")]=0; second[strcspn(second,"\r\n")]=0;
    struct tokens tokens={first,second,0}; struct pam_conv conv={conversation,&tokens};
    pam_handle_t *handle=NULL;
    int rc=pam_start("passwd","root",&conv,&handle);
    if (rc==PAM_SUCCESS) rc=pam_chauthtok(handle,0);
    if (handle) pam_end(handle,rc);
    struct spwd *entry=getspnam("root");
    const char *hash=entry ? entry->sp_pwdp : "*";
    const char *algorithm=strncmp(hash,"$y$",3)==0 ? "yescrypt" : strncmp(hash,"$6$",3)==0 ? "sha512" : "other";
    // Only public outcomes leave this isolated process; never print credentials,
    // conversation messages, shadow entries or password hashes.
    printf("rc=%d algorithm=%s first=%d second=%d\n",rc,algorithm,verifies(first,hash),verifies(second,hash));
    explicit_bzero(first,a);explicit_bzero(second,b);free(first);free(second);return 0;
}

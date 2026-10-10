#include <stdio.h>
#include <sys/timex.h>

int main(void) {
    struct timex value = {0};
    /* Always modes=0; no clock writes and no CAP_SYS_TIME are requested. */
    int state = adjtimex(&value);
    if (state < 0) return 1;
    printf("%d %u %ld %ld\n", state, (unsigned)value.status,
           value.maxerror, value.esterror);
    return 0;
}

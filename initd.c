# include "ssh.h"

static void
create()
{
    compile_object(SSHD);
    compile_object(SSH_USERD);
}

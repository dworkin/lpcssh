# include <kernel/kernel.h>
# include <kernel/user.h>

# define SSH_DEBUG(level, mesg) ((level) <= SSH_DEBUG_LEVEL ? DRIVER->message("SSH:debug" + (level) + ": " + (mesg) + "\n") : 0)

# define SSH_GLUE			SSH_KERNEL_GLUE
# define SSH_GLUE_CALL			(previous_program() == LIB_CONN)
# define SSH_GLUE_RLIMITS(r, f, a)	r = call_limited(#f, a)

# define SSH_KERNEL_GLUE	"/usr/System/lib/ssh_kernel"
# define SSHD			"/usr/System/sys/kernel_sshd"
# define SSH_UTILS		"/usr/System/lib/ssh_utils"
# define SSH_TRANSPORT		"/usr/System/lib/ssh"
# define SSH_CONNECTION		"/usr/System/obj/ssh_connection"
# define SSH_USER		"/usr/System/obj/kernel_user"
# define SSH_WIZTOOL		"/usr/System/obj/kernel_wiztool"
# define SSH_USERD		"/usr/System/sys/kernel_telnetd"

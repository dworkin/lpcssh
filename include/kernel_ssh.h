# include <kernel/kernel.h>
# include <kernel/user.h>

# define SSH_DEBUG(level, mesg) ((level) <= SSH_DEBUG_LEVEL ? DRIVER->message("SSH:debug" + (level) + ": " + (mesg) + "\n") : 0)

# define SSH_GLUE			SSH_KERNEL_GLUE
# define SSH_GLUE_CALL			(previous_program() == LIB_CONN)
# define SSH_GLUE_RLIMITS(r, f, a)	r = call_limited(#f, a)

# define SSH_KERNEL_GLUE	USR_DIR + "/System/lib/ssh_kernel"
# define SSHD			USR_DIR + "/System/sys/kernel_sshd"
# define SSH_UTILS		USR_DIR + "/System/lib/ssh_utils"
# define SSH_TRANSPORT		USR_DIR + "/System/lib/ssh"
# define SSH_CONNECTION		USR_DIR + "/System/obj/ssh_connection"
# define SSH_USER		USR_DIR + "/System/obj/kernel_user"
# define SSH_WIZTOOL		USR_DIR + "/System/obj/kernel_wiztool"
# define SSH_USERD		USR_DIR + "/System/sys/kernel_telnetd"

# define ASN1_UTILS		USR_DIR + "/System/lib/asn1_utils"

# include <config.h>

# define SSH_DEBUG(level, mesg) ((level) <= SSH_DEBUG_LEVEL ? DRIVER->ssh_message("SSH:debug" + (level) + ": " + (mesg) + "\n") : 0)

# define SSH_GLUE			SSH_MELVILLE_GLUE
# define SSH_GLUE_CALL			(!previous_object())
# define SSH_GLUE_RLIMITS(r, f, a)	do { rlimits (50; 3000000) { r = f(a); } } while(0)

# define SSH_MELVILLE_GLUE	"/system/ssh/lib/ssh_melville"
# define SSHD			"/system/ssh/sys/melville_sshd"
# define SSH_UTILS		"/system/ssh/lib/ssh_utils"
# define SSH_TRANSPORT		"/system/ssh/lib/ssh"
# define SSH_CONNECTION		"/system/ssh/obj/ssh_connection"
# define SSH_USER		"/system/ssh/obj/melville_user"


/* compatibility */
# define TRUE			1
# define FALSE			0

# define MODE_DISCONNECT	0
# define MODE_RAW		1
# define MODE_NOCHANGE		2
# define MODE_UNBLOCK		3

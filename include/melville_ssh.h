# include <config.h>

# define SSH_DEBUG(level, mesg) ((level) <= SSH_DEBUG_LEVEL ? DRIVER->message("SSH:debug" + (level) + ": " + (mesg) + "\n") : 0)

# define SSH_GLUE		SSH_MELVILLE_GLUE
# define SSH_GLUE_CALL		(previous_program() == LIB_CONN)
# define SSH_GLUE_RLIMITS(f, a)	f(a)

# define SSH_MELVILLE_GLUE	"/secure/ssh/lib/ssh_melville"
# define SSHD			"/secure/ssh/sys/melville_sshd"
# define SSH_UTILS		"/secure/ssh/lib/ssh_utils"
# define SSH_TRANSPORT		"/secure/ssh/lib/ssh"
# define SSH_CONNECTION		"/secure/ssh/obj/ssh_connection"

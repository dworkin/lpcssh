# include "ssh.h"
# include <type.h>


# define DEBUG SSH_DEBUG

/* ========================================================================= *
 *			       SSH glue for Melville			     *
 * ========================================================================= */

static void start_transport(string str);      /* supplied by transport layer */
static void create_ssh();

static int user_input(string str);

/*
 * NAME:	message()
 * DESCRIPTION:	send a message to the other side
 */
static int message(string str)
{
    return ::send_message(str);
}

static void __send_message(string str)
{
    ::send_message(str);
}

static void send_message(mixed arg)
{
    if (typeof(arg) == T_STRING) {
	message(arg);
    }
}

static int message_done()
{
    return MODE_RAW;
}

/*
 * NAME:	set_mode()
 * DESCRIPTION:	dummy function
 */
static void set_mode(int mode)
{
}

/*
 * NAME:	create_glue()
 * DESCRIPTION:	dummy function
 */
static void create_glue()
{
}

object query_user()
{
    /* XXX */
}

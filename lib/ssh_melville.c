# include "ssh.h"
# include <type.h>


# define DEBUG SSH_DEBUG

/* ========================================================================= *
 *			       SSH glue for Melville			     *
 * ========================================================================= */

static void start_transport(string str);      /* supplied by transport layer */
static void create_ssh();

static int user_input(string str);
object query_player();

private string name;		/* user name */
private int tried_password;	/* password tried before? */

/*
 * NAME:	message()
 * DESCRIPTION:	send an (encrypted) message, used by SSH layer
 */
static int message(string str)
{
    return ::send_message(str);
}

/*
 * NAME:	__send_message()
 * DESCRIPTION:	low-level send_message used to send version string
 */
static void __send_message(string str)
{
    ::send_message(str);
}

/*
 * NAME:	message_done()
 * DESCRIPTION:	called by SSH layer when ready for more output, change this
 *		function if you want flow control
 */
static int message_done()
{
    return MODE_RAW;	/* always return this */
}

/*
 * NAME:	set_mode()
 * DESCRIPTION:	not used
 */
static void set_mode(int mode)
{
}

/*
 * NAME:	ssh_get_user()
 * DESCRIPTION:	check if user exists and can login
 */
static int ssh_get_user(string str)
{
    if (name) {
	return (str == name);
    } else {
	name = str;
	user_input(str);
	return (this_object() != nil);
    }
}

/*
 * NAME:	ssh_check_password()
 * DESCRIPTION:	check whether a supplied password is correct
 */
static int ssh_check_password(string str)
{
    user_input(str);
    return (this_object() && query_player()->query_name() == name);
}

/*
 * NAME:	ssh_do_login()
 * DESCRIPTION:	actually login the user
 */
static void ssh_do_login()
{
}

/*
 * NAME:	create_glue()
 * DESCRIPTION:	initialize glue (but there is nothing to do)
 */
static void create_glue()
{
}

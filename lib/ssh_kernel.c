# include "ssh.h"

# define DEBUG SSH_DEBUG

inherit conn LIB_CONN;
inherit user LIB_USER;


/* ========================================================================= *
 *			SSH glue for the kernel library                      *
 * ========================================================================= */

static void start_transport(string str);      /* supplied by transport layer */


/*
 * NAME:	message()
 * DESCRIPTION:	send a message to the other side
 */
static int message(string str)
{
    return user::message(str);
}

/*
 * NAME:	message_done()
 * DESCRIPTION:	forward message_done to user
 */
static int message_done()
{
    object user;
    int mode;

    user = query_user();
    if (user) {
	mode = user->message_done();
	if (mode == MODE_DISCONNECT || mode >= MODE_UNBLOCK) {
	    return mode;
	}
    }
    return MODE_NOCHANGE;
}

/*
 * NAME:	login()
 * DESCRIPTION:	accept a SSH connection
 */
int login(string str)
{
    if (previous_program() == LIB_CONN) {
	user::connection(previous_object());
	previous_object()->set_mode(MODE_RAW);
	start_transport(str);
    }
    return MODE_RAW;
}

/*
 * NAME:	logout()
 * DESCRIPTION:	disconnect
 */
void logout(int quit)
{
    if (previous_program() == LIB_CONN) {
	conn::close(nil, quit);
	if (quit) {
	    destruct_object(this_object());
	}
    }
}

/*
 * NAME:	set_mode()
 * DESCRIPTION:	pass on mode changes to the real connection object
 */
void set_mode(int mode)
{
    if (SYSTEM() && mode >= MODE_UNBLOCK) {
	query_conn()->set_mode(mode);
    }
}

/*
 * NAME:	user_input()
 * DESCRIPTION:	send input to user object
 */
static int user_input(string str)
{
    return conn::receive_message(nil, str);
}

/*
 * NAME:	datagram_challenge()
 * DESCRIPTION:	there is no datagram channel to be opened
 */
void datagram_challenge(string str)
{
}

/*
 * NAME:	datagram()
 * DESCRIPTION:	don't send a datagram to the client
 */
int datagram(string str)
{
    return 0;
}

/*
 * NAME:	disconnect()
 * DESCRIPTION:	forward a disconnect to the connection
 */
void disconnect()
{
    if (previous_program() == LIB_USER) {
	user::disconnect();
    }
}

/*
 * NAME:	create()
 * DESCRIPTION:	initialize ssh kernel glue
 */
static void create()
{
    conn::create("telnet");	/* pretend */
}
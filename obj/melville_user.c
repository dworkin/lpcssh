# include "/system/ssh/include/ssh.h"
# include <type.h>

inherit ssh SSH_CONNECTION;
inherit user "/system/user";

private string buffer;	/* buffered input for first line */

/*
 * NAME:	create()
 * DESCRIPTION:	initialize SSH user object
 */
void create()
{
    ssh::create_ssh();
    user::create();
    buffer = "";
}

/*
 * NAME:	open()
 * DESCRIPTION:	called when a new connection is opened
 */
static void open()
{
    __send_message(SSHD->query_version() + "\r\n");
    user::open();	/* initialize but no messages yet */
}

/*
 * NAME:	receive_message()
 * DESCRIPTION:	receive a message from the other side
 */
static void receive_message(string str)
{
    if (buffer) {
	string version;

	/*
	 * Get the first line of input, and check whether it is a valid
	 * SSH 2.0 version string.
	 */
	catch {
	    buffer += str;
	} : error("Connection line buffer overflow");

	if (sscanf(buffer, "%s\r\n%s", version, buffer) != 0 ||
	    sscanf(buffer, "%s\n%s", version, buffer) != 0) {
	    if (sscanf(version, "SSH-2.0-%*s") == 0) {
		__send_message("Protocol mismatch.\r\n");
		destruct_object(this_object());
	    } else {
		str = buffer;
		buffer = nil;
		ssh::start_transport(version);

		if (strlen(str) == 0) {
		    return;
		}
	    }
	} else {
	    return;
	}
    }

    if (ssh::receive_message(str) == MODE_DISCONNECT) {
	destruct_object(this_object());
    }
}

/*
 * NAME:	user_input()
 * DESCRIPTION:	used by the SSH layer to forward received and decrypted data
 */
static int user_input(string str)
{
    user::receive_message(str);
    return MODE_RAW;
}

/*
 * NAME:	send_message()
 * DESCRIPTION:	intercept data from the user object and encrypt it
 */
static int send_message(mixed arg)
{
    if (typeof(arg) == T_STRING) {
	return (ssh::message(arg)) ? strlen(arg) : 0;
    }
    return TRUE;
}

/*
 * NAME:	message_done()
 * DESCRIPTION:	forward to the SSH layer
 */
static void message_done()
{
    if (ssh::message_done() == MODE_DISCONNECT) {
	destruct_object(this_object());
    }
}

# include "/system/ssh/include/ssh.h"
# include <type.h>

inherit ssh SSH_CONNECTION;
inherit user "/system/user";

private string buffer;

void create()
{
    ssh::create();
    user::create();
    buffer = "";
}

void open()
{
    __send_message(SSHD->query_version() + "\r\n");
    user::open();	/* initialize but no messages yet */
}

void receive_message(string str)
{
    if (buffer) {
	int len;
	string head, pre;

	catch {
	    buffer += str;
	} : error("Connection line buffer overflow");

	if (sscanf(buffer, "%s\r\n%s", str, buffer) != 0 ||
	    sscanf(buffer, "%s\n%s", str, buffer) != 0) {
	    while (sscanf(str, "%s\b%s", head, str) != 0) {
		while (sscanf(head, "%s\x7f%s", pre, head) != 0) {
		    len = strlen(pre);
		    if (len != 0) {
			head = pre[0 .. len - 2] + head;
		    }
		}
		len = strlen(head);
		if (len != 0) {
		    str = head[0 .. len - 2] + str;
		}
	    }
	    while (sscanf(str, "%s\x7f%s", head, str) != 0) {
		len = strlen(head);
		if (len != 0) {
		    str = head[0 .. len - 2] + str;
		}
	    }

	    if (sscanf(str, "SSH-2.0-%*s") == 0) {
		__send_message("Protocol mismatch.\r\n");
		destruct_object(this_object());
	    } else {
		ssh::start_transport(str);

		str = buffer;
		buffer = nil;
		if (strlen(str) != 0 &&
		    ssh::receive_message(str) == MODE_DISCONNECT) {
		    destruct_object(this_object());
		}
	    }
	}
    } else if (ssh::receive_message(str) == MODE_DISCONNECT) {
	destruct_object(this_object());
    }
}

static int user_input(string str)
{
    user::receive_message(str);
    return MODE_RAW;
}

static int send_message(mixed arg)
{
    if (typeof(arg) == T_STRING) {
	return (ssh::message(arg)) ? strlen(arg) : 0;
    }
    return TRUE;
}

void message_done()
{
    if (ssh::message_done() == MODE_DISCONNECT) {
	destruct_object(this_object());
    }
}

# include "/system/ssh/include/ssh.h"

inherit ssh SSH_CONNECTION;
inherit user "/system/user";

private string buffer;
private int first_line;

void create()
{
    ssh::create();
    user::create();
    buffer = "";
    first_line = TRUE;
}

void open()
{
    __send_message(SSHD->query_version() + "\r\n");
}

void receive_message(string str)
{
    int mode, len;
    string head, pre;

    catch {
	buffer += str;
    } : error("Connection line buffer overflow");

    while (this_object()) {
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

	    if (ssh::receive_message(str) == MODE_DISCONNECT) {
		destruct_object(this_object());
	    }
	} else {
	    break;
	}
    }
}

void message_done()
{
    if (ssh::message_done() == MODE_DISCONNECT) {
	destruct_object(this_object());
    }
}

# include <kernel/kernel.h>
# include <kernel/user.h>
# include <kernel/rsrc.h>

inherit LIB_CONN;
inherit rsrc API_RSRC;

# define SSH		"/usr/System/obj/ssh"


object userd;		/* user daemon */
string version;		/* version string */
string host_key;	/* private host key */
string pub_host_key;	/* public host key */

# define BASE64 ("...........................................\x3e..." +   \
		 "\x3f\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d...=..." +  \
		 "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c" + \
		 "\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19" + \
		 "......" +                                               \
		 "\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26" + \
		 "\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33" + \
		 "...................................................." + \
		 "...................................................." + \
		 ".............................")

/*
 * NAME:	base64_decode()
 * DESCRIPTION:	decode a base64 string
 */
private string base64_decode(string str)
{
    string result, bits;
    int i, len, b1, b2, b3, b4;

    result = "";
    bits = "...";
    for (i = 0, len = strlen(str); i < len; i += 4) {
	b1 = BASE64[str[i]];
	b2 = BASE64[str[i + 1]];
	b3 = BASE64[str[i + 2]];
	b4 = BASE64[str[i + 3]];
	bits[0] = (b1 << 2) | (b2 >> 4);
	bits[1] = (b2 << 4) | (b3 >> 2);
	bits[2] = (b3 << 6) | b4;
	result += bits;
    }

    if (b3 == '=') {
	return result[.. strlen(result) - 3];
    } else if (b4 == '=') {
	return result[.. strlen(result) - 2];
    }
    return result;
}

/*
 * NAME:	create()
 * DESCRIPTION:	initialize ssh connection daemon
 */
static create()
{
    string str;

    /*
     * read private host key
     */
    str = read_file("~/keys/id_dsa");
    if (!str) {
	error("No host key");
    }
    if (sscanf(str, "-----BEGIN DSA PRIVATE KEY-----%s" +
		    "-----END DSA PRIVATE KEY-----", str) == 0) {
	error("Bad host key");
    }
    str = implode(explode(str, "\r"), "");
    sscanf(str, "%*s\n\n%s", str);	/* skip possible comments */
    host_key = base64_decode(implode(explode(str, "\n"), ""));

    /*
     * read public host key
     */
    str = read_file("~/keys/id_dsa.pub");
    if (!str) {
	error("No public host key");
    }
    if (sscanf(str, "ssh-dss %s ", str) == 0) {
	error("Bad public host key");
    }
    pub_host_key = base64_decode(str);

    if (hash_crc32(host_key, pub_host_key) == 6922236) {
	DRIVER->message("*WARNING*\n\nYou are using pre-configured host keys.  To install your own host keys, run the\ncommand 'ssh-keygen -t dsa' and save the files in mudlib directory\n/usr/System/keys.\n\n");
    }

    /*
     * initialize
     */
    rsrc::create();
    rsrc::rsrc_set_limit("System", "ticks", 3000000);
    compile_object(SSH);
    userd = find_object(USERD);
    userd->set_binary_manager(0, this_object());
    version = "SSH-2.0-LPCssh_1.0";
}


/*
 * NAME:	select()
 * DESCRIPTION:	select protocol
 */
object select(string protocol)
{
    if (previous_object() == userd && sscanf(protocol, "SSH-2.0-%*s") != 0) {
	return clone_object(SSH);
    }
    return this_object();
}

/*
 * NAME:	login()
 * DESCRIPTION:	display an errormessage and disconnect
 */
int login(string str)
{
    previous_object()->message("Protocol mismatch.\r\n");
    return MODE_DISCONNECT;
}


/*
 * NAME:	query_timeout()
 * DESCRIPTION:	return login timeout
 */
int query_timeout(object obj)
{
    return 30;
}

/*
 * NAME:	query_banner()
 * DESCRIPTION:	return login banner
 */
string query_banner(object obj)
{
    return version + "\r\n";
}

/*
 * NAME:	query_version()
 * DESCRIPTION:	return the version string
 */
string query_version()
{
    return version;
}

/*
 * NAME:	query_host_key()
 * DESCRIPTION:	return the (private) host key
 */
string query_host_key()
{
    if (previous_program() == SSH) {
	return host_key;
    }
}

/*
 * NAME:	query_pub_host_key()
 * DESCRIPTION:	return the public host key
 */
string query_pub_host_key()
{
    return pub_host_key;
}

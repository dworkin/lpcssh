# include "/system/ssh/include/ssh.h"

private inherit SSH_UTILS;

string version;		/* version string */
string host_key;	/* private host key */
string pub_host_key;	/* public host key */

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
    str = read_file("/system/ssh/keys/id_dsa");
    if (!str) {
	error("No host key");
    }
    host_key = parse_private_key(str);
    if (!host_key) {
	error("Bad host key");
    }

    /*
     * read public host key
     */
    str = read_file("/system/ssh/keys/id_dsa.pub");
    if (!str) {
	error("No public host key");
    }
    pub_host_key = parse_public_key(str);
    if (!pub_host_key) {
	error("Bad public host key");
    }

    if (hash_crc32(host_key, pub_host_key) == 6922236) {
	DRIVER->ssh_message("*WARNING*\n\nYou are using pre-configured host keys.  To install your own host keys, run the\ncommand 'ssh-keygen -t dsa' and save the files in mudlib directory\n/system/ssh/keys.\n\n");
    }

    /*
     * initialize
     */
    version = "SSH-2.0-LPCssh_1.0";
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
 * NAME:        valid_public_key()
 * DESCRIPTION: Check the ~/.ssh/ directory to see if this is an acceptable
 *              public key.
 */
private int valid_public_key(string name, string publickey)
{
    string str;

    str = read_file("~" + name + "/.ssh/id_dsa.pub");
    if (str) {
	string pkey;

	sscanf(str, "%s\n", str);
	pkey = parse_public_key(str);
	if (pkey && pkey == publickey) {
	    return 1;
	}
    }
    str = read_file("~" + name + "/.ssh/authorized_keys");
    if (str) {
	int    i, sz;
	string *lines;

	lines = explode(implode(explode(str, "\r"), "\n"), "\n");
	sz = sizeof(lines);
	for (i = 0; i < sz; i++) {
	    if (lines[i] && strlen(lines[i])) {
		string pkey;

		pkey = parse_public_key(str);
		if (pkey && pkey == publickey) {
		    return 1;
		}
	    }
	}
    }
    return 0;
}

/*
 * NAME:	query_host_key()
 * DESCRIPTION:	return the (private) host key
 */
string query_host_key()
{
    if (previous_program() == SSH_TRANSPORT) {
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

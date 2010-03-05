/*
 * a minimal user object replacement that really only adds a single
 * function, do_login().
 */

# define save_object(path)		this_object()->ssh_save_object(path)
# define clone_object(path, owner)	this_object()->ssh_clone_object(path, owner)

# include "/kernel/obj/user.c"		/* all right, this is cheating */

# undef save_object
# undef clone_object

# include "ssh.h"

/*
 * NAME:	ssh_save_object()
 * DESCRIPTION:	don't
 */
static void ssh_save_object(string path)
{
}

/*
 * NAME:	ssh_clone_object()
 * DESCRIPTION:	clone a different wiztool
 */
static object ssh_clone_object(string path, string owner)
{
    if (path == DEFAULT_WIZTOOL) {
	path = SSH_WIZTOOL;
    }
    return clone_object(path, owner);
}

/*
 * NAME:        do_login()
 * DESCRIPTION: Trust the ~System code to have authenticated the user and
 *              log it in.  This function is the only real change compared to
 *		the standard user object in the kernel library; it exists so
 *		that players can login using public key authentication.
 */
void do_login()
{
    if (SYSTEM() && query_conn() != previous_object()) {
	connection(previous_object());
	state[previous_object()] = STATE_NORMAL;
	tell_audience(Name + " logs in.\n");
	if (!wiztool &&
	    (name == "admin" || sizeof(query_users() & ({ name })) != 0)) {
	    wiztool = clone_object(SSH_WIZTOOL, name);
	}
    }
}

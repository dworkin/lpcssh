# include <kernel/kernel.h>
# include <kernel/user.h>

# include "ssh.h"

inherit LIB_USER;

object  userd;
string  banner;
mapping names;

/*
 * NAME:        create()
 * DESCRIPTION: initialize telnet daemon
 */
static create()
{   
    compile_object(SSH_USER);
    compile_object(SSH_WIZTOOL);

    userd = find_object(USERD);
    userd->set_telnet_manager(0, this_object());

    banner = "\n" +
             "Welcome to your local SSH-LPC enabled lib.\n" +
             "\n" +
             "login: ";
    names = ([ ]);
}

/*
 * NAME:        select()
 * DESCRIPTION: select user object based on loginname
 */
object select(string name)
{   
    if (previous_object() == userd) {
        object obj;

        obj = names[name];
        return (obj) ? obj : clone_object(SSH_USER);
    }
}

/*
 * NAME:        query_timeout()
 * DESCRIPTION: return the login timeout
 */
int query_timeout(object obj)
{
    return DEFAULT_TIMEOUT;
}

/*
 * NAME:        set_banner()
 * DESCRIPTION: set the login banner
 */
void set_banner(string str)
{
    if (SYSTEM()) {
        banner = str;
    }
}
 
/*
 * NAME:        query_banner()
 * DESCRIPTION: return the login banner
 */
string query_banner(object obj)
{
    return banner;
}
 
/*
 * NAME:        login()
 * DESCRIPTION: display an errormessage and disconnect
 */
int login(string str)
{
    previous_object()->message("\"" + str + "\" is not a valid name.\n\n");
    return MODE_DISCONNECT;
}

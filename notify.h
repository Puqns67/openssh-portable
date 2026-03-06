#include <netdb.h>
#include <pwd.h>
#include <stdbool.h>

#include "hostfile.h"
#include "packet.h"

#include "auth.h"
#include "channels.h"
#include "session.h"

void do_login_notify(Session *s, char *command);
void do_extra_motd(Session *s);

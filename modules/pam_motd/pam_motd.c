/* pam_motd module */

/*
 * Modified for pam_motd by Ben Collins <bcollins@debian.org>
 *
 * Based off of:
 * $Id$
 *
 * Written by Michael K. Johnson <johnsonm@redhat.com> 1996/10/24
 *
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <syslog.h>

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_SESSION
#define DEFAULT_MOTD	"/etc/motd"

#include <security/pam_modules.h>
#include <security/pam_modutil.h>

/* --- session management functions (only) --- */

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		      int argc UNUSED, const char **argv UNUSED)
{
     return PAM_IGNORE;
}

static char default_motd[] = DEFAULT_MOTD;

static void display_file(pam_handle_t *pamh, const char *motd_path)
{
    int fd;
    char *mtmp = NULL;
    while ((fd = open(motd_path, O_RDONLY, 0)) >= 0) {
	struct stat st;
	/* fill in message buffer with contents of motd */
	if ((fstat(fd, &st) < 0) || !st.st_size || st.st_size > 0x10000)
	    break;
	if (!(mtmp = malloc(st.st_size+1)))
	    break;
	if (pam_modutil_read(fd, mtmp, st.st_size) != st.st_size)
	    break;
	if (mtmp[st.st_size-1] == '\n')
	    mtmp[st.st_size-1] = '\0';
	else
	    mtmp[st.st_size] = '\0';
	pam_info (pamh, "%s", mtmp);
	break;
    }
    _pam_drop (mtmp);
    if (fd >= 0)
	close(fd);
}

int display_legal(pam_handle_t *pamh)
{
    int retval = PAM_IGNORE, rc;
    char *user = NULL;
    char *dir = NULL;
    char *flag = NULL;
    struct passwd *pwd = NULL;
    struct stat s;
    int f;
    /* Get the user name to determine if we need to print the disclaimer */
    rc = pam_get_item(pamh, PAM_USER, &user);
    if (rc == PAM_SUCCESS && user != NULL && *(const char *)user != '\0')
    {
        PAM_MODUTIL_DEF_PRIVS(privs);

        /* Get the password entry */
        pwd = pam_modutil_getpwnam (pamh, user);
        if (pwd != NULL)
        {
            if (pam_modutil_drop_priv(pamh, &privs, pwd)) {
                pam_syslog(pamh, LOG_ERR,
                           "Unable to change UID to %d temporarily\n",
                           pwd->pw_uid);
                retval = PAM_SESSION_ERR;
                goto finished;
            }

            if (asprintf(&dir, "%s/.cache", pwd->pw_dir) == -1 || !dir)
                goto finished;
            if (asprintf(&flag, "%s/motd.legal-displayed", dir) == -1 || !flag)
                goto finished;

            if (stat(flag, &s) != 0)
            {
                display_file(pamh, "/etc/legal");
                mkdir(dir, 0700);
                f = open(flag, O_WRONLY|O_CREAT|O_EXCL,
                         S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
                if (f>=0) close(f);
            }

finished:
            if (pam_modutil_regain_priv(pamh, &privs)) {
                pam_syslog(pamh, LOG_ERR,
                           "Unable to change UID back to %d\n", privs.old_uid);
                retval = PAM_SESSION_ERR;
            }

            _pam_drop(flag);
            _pam_drop(dir);
        }
    }
    return retval;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
    int retval = PAM_IGNORE;
    int do_update = 1;
    const char *motd_path = NULL;
    struct stat st;

    if (flags & PAM_SILENT) {
	return retval;
    }

    for (; argc-- > 0; ++argv) {
        if (!strncmp(*argv,"motd=",5)) {

            motd_path = 5 + *argv;
            if (*motd_path != '\0') {
                D(("set motd path: %s", motd_path));
	    } else {
		motd_path = NULL;
		pam_syslog(pamh, LOG_ERR,
			   "motd= specification missing argument - ignored");
	    }
	}
	else if (!strcmp(*argv,"noupdate")) {
		do_update = 0;
	}
	else
	    pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
    }

    if (motd_path == NULL)
	motd_path = default_motd;

    /* Run the update-motd dynamic motd scripts, outputting to /run/motd.dynamic.
       This will be displayed only when calling pam_motd with
       motd=/run/motd.dynamic; current /etc/pam.d/login and /etc/pam.d/sshd
       display both this file and /etc/motd. */
    if (do_update && (stat("/etc/update-motd.d", &st) == 0)
        && S_ISDIR(st.st_mode))
    {
	mode_t old_mask = umask(0022);
	if (!system("/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts /etc/update-motd.d > /run/motd.dynamic.new"))
	    rename("/run/motd.dynamic.new", "/run/motd.dynamic");
	umask(old_mask);
    }

    /* Display the updated motd */
    display_file(pamh, motd_path);

    /* Display the legal disclaimer only if necessary */
    retval = display_legal(pamh);

    return retval;
}

/* end of module definition */

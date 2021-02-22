/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <library.h>
#include <networking/streams/stream_unix.h>

#include <errno.h>
#include <unistd.h>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#else
#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>
#endif

bool change_owner(int fd, struct sockaddr_un *addr)
{
#ifdef WIN32
    /* Change owner of socket */
    /* https://docs.microsoft.com/en-us/windows/win32/secauthz/taking-object-ownership-in-c-- */
	SECURITY_DESCRIPTOR *security_descriptor = malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);

	PACL pACL = NULL;
	EXPLICIT_ACCESS ea[2];
	SID *pAdminSID = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

	char buf[512];
	int ret = FALSE;
        /* BUILTIN\Administrator  */
	if(!AllocateAndInitializeSid(&SIDAuthNT, 2,
                     SECURITY_BUILTIN_DOMAIN_RID,
                     DOMAIN_ALIAS_RID_ADMINS,
                     0, 0, 0, 0, 0, 0,
                     (void **) &pAdminSID)) 
	{
		DBG1(DBG_LIB, "Failed to initialize SID: %s", dlerror_mt(buf, sizeof(buf)));
		goto cleanup;
	}

	memset(ea, 0, sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance= NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[0].Trustee.ptstrName  = (LPTSTR) pAdminSID;
	if (!InitializeSecurityDescriptor(security_descriptor, SECURITY_DESCRIPTOR_REVISION))
	{
		DBG1(DBG_LIB, "Failed to initialize security descriptor: %s", dlerror_mt(buf, sizeof(buf)));
		goto cleanup;
	}
	if ((ret=SetEntriesInAcl(1, ea, NULL, &pACL)) != ERROR_SUCCESS)
	{
		DBG1(DBG_LIB, "Failed to set ACL entries: %s", human_readable_error(buf, ret, sizeof(buf)));
		goto cleanup;		
	}
	if (!(ret=SetSecurityDescriptorDacl(security_descriptor, TRUE, pACL, FALSE)))
	{
		DBG1(DBG_LIB, "Failed to set security descriptor in ACL: %s", dlerror_mt(buf, sizeof(buf)));
		goto cleanup;
	}

    if(SetNamedSecurityInfo(
    addr->sun_path,
    SE_FILE_OBJECT,
    DACL_SECURITY_INFORMATION,
    NULL, NULL,                  
    pACL,                        
    NULL) == ERROR_SUCCESS)
    {
        ret = TRUE;
    }
    
cleanup:
        FreeSid(pAdminSID);
        return ret;
#else
	if (lib->caps->check(lib->caps, CAP_CHOWN))
	{
		if (chown(addr->sun_path, lib->caps->get_uid(lib->caps),
				  lib->caps->get_gid(lib->caps)) != 0)
		{
			DBG1(DBG_NET, "changing socket owner/group for '%s' failed: %s",
				 addr->sun_path, strerror(errno));
		}
	}
	else
	{
		if (chown(addr->sun_path, -1, lib->caps->get_gid(lib->caps)) != 0)
		{
			DBG1(DBG_NET, "changing socket group for '%s' failed: %s",
				 addr->sun_path, strerror(errno));
		}
	}
        return TRUE;
#endif
}
/**
 * See header
 */
stream_service_t *stream_service_create_unix(char *uri, int backlog)
{
	struct sockaddr_un addr;
	mode_t old;
	int fd, len;

	len = stream_parse_uri_unix(uri, &addr);
	if (len == -1)
	{
		DBG1(DBG_NET, "invalid stream URI: '%s'", uri);
		return NULL;
	}
	if (!lib->caps->check(lib->caps, CAP_CHOWN))
	{	/* required to chown(2) service socket */
		DBG1(DBG_NET, "cannot change ownership of socket '%s' without "
			 "CAP_CHOWN capability. socket directory should be accessible to "
			 "UID/GID under which the daemon will run", uri);
	}
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
	{
		DBG1(DBG_NET, "opening socket '%s' failed: %s", uri, strerror(errno));
		return NULL;
	}
	unlink(addr.sun_path);

	old = umask(S_IRWXO);
	if (bind(fd, (struct sockaddr*)&addr, len) < 0)
	{
		DBG1(DBG_NET, "binding socket '%s' failed: %s", uri, strerror(errno));
		close(fd);
		return NULL;
	}
	umask(old);
	/* Only attempt to change owner of socket if we have CAP_CHOWN. Otherwise,
	 * attempt to change group of socket to group under which charon runs after
	 * dropping caps. This requires the user that charon starts as to:
	 * a) Have write access to the socket dir.
	 * b) Belong to the group that charon will run under after dropping caps. */
        if (!change_owner(fd, &addr))
        {
            DBG1(DBG_NET, "Failed to change owner of socket '%s': %s", uri, strerror(errno));
        }
	if (listen(fd, backlog) < 0)
	{
		DBG1(DBG_NET, "listen on socket '%s' failed: %s", uri, strerror(errno));
		unlink(addr.sun_path);
		close(fd);
		return NULL;
	}
	return stream_service_create_from_fd(fd);
}

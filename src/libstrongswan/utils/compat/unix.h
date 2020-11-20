
#ifndef _AFUNIX_
#define _AFUNIX_

#define UNIX_PATH_MAX 108

typedef struct sockaddr_un
{
     ADDRESS_FAMILY sun_family;
     char sun_path[UNIX_PATH_MAX];
} SOCKADDR_UN, *PSOCKADDR_UN;

#define SIO_AF_UNIX_GETPEERPID _WSAIOR(IOC_VENDOR, 256)

#endif /* _AFUNIX_ */

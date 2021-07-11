#include <sys/types.h>

#define crypt x_crypt
#define encrypt x_encrypt
#include <unistd.h>

#define fd_set x_fd_set
#define ino_t x_ino_t
#define off_t x_off_t
#define loff_t x_loff_t
#define dev_t x_dev_t
#define mode_t x_mode_t
#define uid_t x_uid_t
#define gid_t x_gid_t
#define uint64_t x_uint64_t
#define u_int64_t x_u_int64_t
#define int64_t x_int64_t
#define nlink_t x_nlink_t
#define timer_t x_timer_t
#define blkcnt_t x_blkcnt_t

#include <linux/types.h>

#undef fd_set
#undef ino_t
#undef off_t
#undef dev_t
#undef mode_t
#undef uid_t
#undef gid_t
#undef uint64_t
#undef u_int64_t
#undef int64_t
#undef nlink_t
#undef timer_t
#undef blkcnt_t
#undef crypt
#undef encrypt

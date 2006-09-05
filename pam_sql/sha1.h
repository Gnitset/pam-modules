/*
 *  SHA-1 in C
 *  By Steve Reid <steve@edmweb.com>
 *  100% Public Domain
 *
 *  Version:	$Id$
 */

#ifndef _gnu_radius_sha1_h
#define _gnu_radius_sha1_h

#define SHA1_CTX		_pam_mysql_SHA1_CTX
#define SHA1Transform		_pam_mysql_SHA1Transform
#define SHA1Init		_pam_mysql_SHA1Init
#define SHA1Update		_pam_mysql_SHA1Update
#define SHA1Final       	_pam_mysql_SHA1Final

typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(unsigned long state[5], const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, const unsigned char *data, unsigned int len);
void SHA1Final(unsigned char digest[20], SHA1_CTX *context);

#endif /* !_gnu_radius_sha1_h */

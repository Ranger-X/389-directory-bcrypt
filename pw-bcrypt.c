/*
 * Written by Wouter Clarie <wclarie at gmail.com>
 *
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2014 Wouter Clarie and it is hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * It is my intent that you should be able to use this on your system, as part
 * of a software package, or anywhere else to improve security, ensure
 * compatibility, or for any other purpose. I would appreciate it if you give
 * credit where it is due and keep your modifications in the public domain as
 * well, but I don't require that in order to let you place this code and any
 * modifications you make under a license of your choice.
 *
 * Please read the README file in this directory.
 */

#include <stdlib.h>

//#include "portable.h"
//#include <ac/string.h>
#include "lber.h"
//#include "util.h"

#include <slapi-plugin.h>
#include <slapi-private.h>
#include <ssl.h>
#include <nspr.h>
#include <plbase64.h>
#include <ldif.h>

#include "crypt_blowfish.h"
//#include "crypt_sha256.h"

static char *plugin_name = "PwdStorageBCryptPlugin";

#ifdef SLAPD_BCRYPT_DEBUG
#define _DEBUG(args...) slapi_log_err(SLAPI_LOG_PLUGIN, plugin_name, __VA_ARGS__)
#else
#define _DEBUG(args...)
#endif

/* Always generate 'b' type hashes for new passwords to match
 * OpenBSD 5.5+ behaviour.
 * See first http://www.openwall.com/lists/announce/2011/07/17/1 and then
 * http://www.openwall.com/lists/announce/2014/08/31/1
 */
#define BCRYPT_DEFAULT_PREFIX		"$2b"

/* Default work factor as currently used by the OpenBSD project for normal
 * accounts. Only used when no work factor is supplied in the slapd.conf
 * when loading the module. See README for more information.
 */
#define BCRYPT_DEFAULT_WORKFACTOR        10
#define BCRYPT_MIN_WORKFACTOR            4
#define BCRYPT_MAX_WORKFACTOR           32

#define BCRYPT_SALT_SIZE                22
#define BCRYPT_OUTPUT_SIZE              61

/*
 * Some defines from openLDAP
 * */

#define LUTIL_PASSWD_OK		(0)
#define LUTIL_PASSWD_ERR	(-1)
#define AC_MEMCPY( d, s, n ) (SAFEMEMCPY((d),(s),(n)))
#define BER_STRLENOF(s)	(sizeof(s)-1)
#define BER_BVC(s)		{ BER_STRLENOF(s), (char *)(s) }

static int bcrypt_workfactor;
const struct berval bcryptscheme = BER_BVC("{BCRYPT}");
//struct berval sha256bcryptscheme = BER_BVC("{SHA256-BCRYPT}");
static Slapi_PluginDesc bcrypt_pdesc = {"blowfish-crypt-password-storage-scheme", "RangerX", "0.0.1", "Salted Blowfish crypt hash algorithm (BCRYPT)"};

/***
 * Function instead of openLDAP's lutil_entropy
 * @param dest
 * @param length
 * @return
 */
int rand_str(char *dest, size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';

    return 0;
}

/**
 * OpenLDAP version from https://github.com/sistason/openldap-sha256-bcrypt
 *
 * @param scheme
 * @param passwd
 * @param hash
 * @param text
 * @return
 */
static int hash_bcrypt(
    const struct berval  *scheme, /* Scheme name to construct output */
    const struct berval  *passwd, /* Plaintext password to hash */
    struct       berval  *hash,	  /* Return value: schema + bcrypt hash */
    const char          **text)	  /* Unused */
{
    _DEBUG("Entering hash_bcrypt\n");

    char bcrypthash[BCRYPT_OUTPUT_SIZE];
    char saltinput[BCRYPT_SALT_SIZE];
    char settingstring[sizeof(BCRYPT_DEFAULT_PREFIX) + 1 + BCRYPT_SALT_SIZE + 1];

    struct berval salt;
    struct berval digest;

    salt.bv_val = saltinput;
    salt.bv_len = sizeof(saltinput);

    _DEBUG("Obtaining entropy for bcrypt: %d bytes\n", (int) salt.bv_len);
    if (rand_str((unsigned char *)salt.bv_val, salt.bv_len - 1) < 0) {
        _DEBUG("Error: cannot get entropy\n");
        return LUTIL_PASSWD_ERR;
    }

    _DEBUG("Generating setting string and salt\n");
    if (_crypt_gensalt_blowfish_rn(BCRYPT_DEFAULT_PREFIX,
                                   bcrypt_workfactor,
                                   saltinput,
                                   BCRYPT_SALT_SIZE,
                                   settingstring,
                                   BCRYPT_OUTPUT_SIZE) == NULL) {
        _DEBUG("Error: _crypt_gensalt_blowfish_rn returned NULL\n");
        return LUTIL_PASSWD_ERR;
    }
    _DEBUG("Setting string: \"%s\"\n", settingstring);

    char *userpassword = passwd->bv_val;
    _DEBUG("Hashing password \"%s\" with settingstring \"%s\"\n",
           userpassword, settingstring);
    if (_crypt_blowfish_rn( userpassword,
                            settingstring,
                            bcrypthash,
                            BCRYPT_OUTPUT_SIZE) == NULL)
        return LUTIL_PASSWD_ERR;

    _DEBUG("bcrypt hash created: \"%s\"\n", bcrypthash);

    digest.bv_len = scheme->bv_len + sizeof(bcrypthash);
    digest.bv_val = (char *) ber_memalloc(digest.bv_len + 1);

    if (digest.bv_val == NULL) {
        return LUTIL_PASSWD_ERR;
    }

    /* No need to base64 encode, as crypt_blowfish already does that */
    AC_MEMCPY(digest.bv_val, scheme->bv_val, scheme->bv_len);
    AC_MEMCPY(&digest.bv_val[scheme->bv_len], bcrypthash, sizeof(bcrypthash));

    digest.bv_val[digest.bv_len] = '\0';
    *hash = digest;

    return LUTIL_PASSWD_OK;
}

/**
 * OpenLDAP version from https://github.com/sistason/openldap-sha256-bcrypt
 */
static int chk_bcrypt(
    const struct berval *scheme, /* Scheme of hashed reference password */
    const struct berval *passwd, /* Hashed password to check against */
    const struct berval *cred,   /* User-supplied password to check */
    const char         **text)   /* Unused */
{
    _DEBUG("Entering chk_bcrypt\n");
    char computedhash[BCRYPT_OUTPUT_SIZE];
    int rc;

    if (passwd->bv_val == NULL) {
        _DEBUG("Error: Stored hash is NULL\n");
        return LUTIL_PASSWD_ERR;
    }

    _DEBUG("Supplied hash: \"%s\"\n", (char *)passwd->bv_val);

    if (passwd->bv_len > BCRYPT_OUTPUT_SIZE) {
        _DEBUG("Error: Stored hash is too large. Size = %d\n",
               (int) passwd->bv_len);
        return LUTIL_PASSWD_ERR;
    }

    _DEBUG("Hashing provided credentials: \"%s\"\n", (char *) cred->bv_val);
    /* No need to base64 decode, as crypt_blowfish already does that */
    if (_crypt_blowfish_rn( (char *) cred->bv_val,
                            (char *) passwd->bv_val,
                            computedhash,
                            BCRYPT_OUTPUT_SIZE) == NULL) {
        _DEBUG("Error: _crypt_blowfish_rn returned NULL\n");
        return LUTIL_PASSWD_ERR;
    }
    _DEBUG("Resulting hash: \"%s\"\n", computedhash);

    _DEBUG("Comparing newly created hash with supplied hash: ");
    rc = slapi_ct_memcmp((char *) passwd->bv_val, computedhash, BCRYPT_OUTPUT_SIZE);
    if (!rc) {
        _DEBUG("match\n");
        return LUTIL_PASSWD_OK;
    }

    _DEBUG("no match\n");
    return LUTIL_PASSWD_ERR;
}
/*
static const struct berval to_sha256(const struct berval *passwd)
{
    _DEBUG("Entering to_sha256\n");

    struct berval sha256_hexpasswd;

    BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, (const unsigned char *) passwd->bv_val, passwd->bv_len);
	sha256_final(&ctx, buf);

    char* hexdigest = (char *) ber_memalloc(SHA256_BLOCK_SIZE*2+1);
    for (int i=0; i<SHA256_BLOCK_SIZE; i++) {
        sprintf(hexdigest + 2*i, "%02x", (unsigned int) buf[i]);
    }
    hexdigest[SHA256_BLOCK_SIZE*2] = '\0';

    _DEBUG("%s -> sha256 %s\n", passwd->bv_val, hexdigest);

	sha256_hexpasswd.bv_val = hexdigest;
	sha256_hexpasswd.bv_len = sizeof(buf);

	return sha256_hexpasswd;
}

static int hash_sha256bcrypt(
    const struct berval  *scheme,
    const struct berval  *passwd,
    struct       berval  *hash,
    const char          **text)
{
    const struct berval sha256_hexpasswd = to_sha256(passwd);
    const int return_val = hash_bcrypt(scheme, &sha256_hexpasswd, hash, text);
    ber_memfree(sha256_hexpasswd.bv_val);
    return return_val;
}

static int chk_sha256bcrypt(
    const struct berval *scheme,
    const struct berval *passwd,
    const struct berval *cred,
    const char         **text)
{
    const struct berval sha256_hexcred = to_sha256(cred);
    const int return_val = chk_bcrypt(scheme, passwd, &sha256_hexcred, text);
    ber_memfree(sha256_hexcred.bv_val);
    return return_val;
}
*/
/**
 *
 * @param pwd
 * @return
 */
char *
bcrypt_pw_enc(const char *pwd)
{
    char *enc = NULL;
    long v;
    static unsigned int seed = 0;

    const struct berval berval_pwd = {.bv_val = pwd, .bv_len = sizeof(*pwd) };
    struct berval  hash;

    if (seed == 0) {
        seed = (unsigned int)slapi_rand();
    }
    //v = slapi_rand_r(&seed);

//    berval_pwd.bv_val = pwd;
//    berval_pwd.bv_len = sizeof(pwd);

    const int return_val = hash_bcrypt(&bcryptscheme, &berval_pwd, &hash, (const char **)"");

    if (return_val == LUTIL_PASSWD_OK) {
        return (hash.bv_val);
    }
}

int bcrypt_pw_cmp(const char *userpwd, const char *dbpwd) {

    const struct berval berval_userpwd = {.bv_val = userpwd, .bv_len = sizeof(*userpwd) };
    const struct berval berval_dbpwd = {.bv_val = dbpwd, .bv_len = sizeof(*dbpwd) };

    return chk_bcrypt(&bcryptscheme, &berval_dbpwd, &berval_userpwd, (const char **)"");
}

int
bcrypt_pwd_storage_scheme_init(Slapi_PBlock *pb)
{
    int rc;

    slapi_log_err(SLAPI_LOG_PLUGIN, plugin_name, "=> bcrypt_pwd_storage_scheme_init\n");

    rc = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                          (void *)SLAPI_PLUGIN_VERSION_01);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                           (void *)&bcrypt_pdesc);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_PWD_STORAGE_SCHEME_ENC_FN,
                           (void *)bcrypt_pw_enc);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_PWD_STORAGE_SCHEME_CMP_FN,
                           (void *)bcrypt_pw_cmp);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_PWD_STORAGE_SCHEME_NAME,
                           "BCRYPT");

    bcrypt_workfactor = BCRYPT_DEFAULT_WORKFACTOR;

    slapi_log_err(SLAPI_LOG_PLUGIN, plugin_name, "<= bcrypt_pwd_storage_scheme_init %d\n\n", rc);

    return (rc);
}

//int init_module(int argc, char *argv[])
//{
//    _DEBUG("Loading bcrypt password module\n");
//
//    int result = 0;
//
//    /* Work factor can be provided in the moduleload statement in slapd.conf. */
//    if (argc > 0) {
//        _DEBUG("Work factor argument provided, trying to use that\n");
//        int work = atoi(argv[0]);
//        if (work &&
//            work >= BCRYPT_MIN_WORKFACTOR &&
//            work <= BCRYPT_MAX_WORKFACTOR) {
//            _DEBUG("Using configuration-supplied work factor %d\n", work);
//            bcrypt_workfactor = work;
//
//        } else {
//            _DEBUG("Invalid work factor. Using default work factor %d\n",
//                   BCRYPT_DEFAULT_WORKFACTOR);
//            bcrypt_workfactor = BCRYPT_DEFAULT_WORKFACTOR;
//        }
//    } else {
//        _DEBUG("No arguments provided. Using default work factor %d\n",
//               BCRYPT_DEFAULT_WORKFACTOR);
//        bcrypt_workfactor = BCRYPT_DEFAULT_WORKFACTOR;
//    }
//
//    result = lutil_passwd_add( &bcryptscheme, chk_bcrypt, hash_bcrypt );
//    _DEBUG("pw-bcrypt: Initialized BCRYPT with work factor %d\n", bcrypt_workfactor);
//
//    result = lutil_passwd_add( &sha256bcryptscheme, chk_sha256bcrypt, hash_sha256bcrypt );
//    _DEBUG("pw-bcrypt: Initialized SHA256-BCRYPT with work factor %d\n", bcrypt_workfactor);
//
//    return result;
//}

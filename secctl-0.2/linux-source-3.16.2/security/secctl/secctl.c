/*
 * secctl Linux UserSpace admin tool Version 0.2
 *
 * Copyright (C) 2014/15 (TomVt / secctlfb * at * t-online dot de)
 *
 *	initial implementation for Kernel 3.16.2-64 x86_64 with 32 bit Userspace
 *
 * Licence:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * ---------------------------------------------------------------------------------
 *
 * This UserSpace admin tool is used to interact with
 *  the KernelSpace LSM via /dev/secctl to
 *
 *  1) add or change rules
 *  2) clear entire rule table
 *  3) change default policy (accept or deny)
 *  4) enable or disable LSM
 *  5a) lock or unlock LSM with password
 *  5b) like 5a + deny any Kernel mount/umount/remount ("lockm")
 *  6a) show entire rule table RT[] (read into UserSpace and call printf)
 *  6b) show entire rule table RT[] (KernelSpace LSM calls printk() to syslog)
 *
 * ---------------------------------------------------------------------------------
 *
 * see README file for an introduction
 *
 * -------------------------------------------------------------------------
 *
 * Open Questions:
 *
 * 1) This program is not tested to work under true 64bit UserSpace.
 * 2) This program is not tested with different LOCALE and UTF settings.
 *    When reading a <filename> or a <password>, we need to do sanity checks
 *    for valid characters. Originally we were using isalnum() and isdigit().
 *    But there is an issue as those functions do respect LOCALE settings,
 *    and we don't know the behavior in different LOCALES. So instead of relying
 *    on those functions, meanwhile we wrote our own versions (isalnum2() and
 *    isdigit2() - see common.h)
 * 3) Should we use capabilities ? 
 *    a) to restrict userspace privileges even further ?
 *    b) to deny a reboot globally (CAP_SYS_BOOT) since there seems no LSM hook that 
 *       would be called if reboot is initiated. This option could prevent a reboot
 *       and should be seen in conjunction with option 5b) lock and deny *mount.
 * 4) What about signals ? Should we safely catch some of the more important ones ?
 * 5) For lock|unlock and SHA256/HMAC we use pre-defined SALT1/2 iff <bootid> is not
 *    available. This is the contrary to a true random SALT, see further
 *    consideration for function sha256_process_password() in file <sha256.h>
 * 
 * ----------------------------------------------------------------------------------
 *
 * STEPs (0 to 7) you might consider for compilation & installation :
 *
 *
 * ------------------------------------------------------------------------------------
 * STEP 0: Compile new kernel with secctl LSM integrated and enabled
 *		(see README how to do this)
 * ------------------------------------------------------------------------------------
 *
 * ------------------------------------------------------------------------------------
 * STEP 1: As we don't want to run this UserSpace admin tool with root privilege, 
 * 		you need to create a new user and group <secctl>
 * ------------------------------------------------------------------------------------
 *
 * > adduser secctl
 *	(usually this command will create a new group <secctl> as well)
 *
 * > cat /etc/passwd | grep secctl
 *   secctl:x:1001:1001::....
 *
 * > cat /etc/group	# (UID=1001, GID=1001 is just an example)
 *   secctl:x:1001:
 *
 * Note:
 *  If this program is started with
 *	UID = SECCTL_UID and
 *	GID = SECCTL_GID
 *  then anything is fine, and we will not change UID/GID at runtime.
 *
 *  If this program is started with (e)UID=0, we drop this
 *  privilege early to 
 *	UID := SECCTL_UID and
 *	GID := SECCTL_GID
 * ------------------------------------------
 * For the example above, one would set
 *
 * 	#define		SECCTL_UID	1001
 * 	#define		SECCTL_GID	1001
 *
 */
#define	SECCTL_UID		1001
#define	SECCTL_GID		1001
 
#if SECCTL_UID < 1 
# error "SECCTL_UID : you need to set this constant to a valid unpriviliged UID !"
#endif
#if SECCTL_GID < 1 
# error "SECCTL_GID : you need to set this constant to a valid unpriviliged GID !"
#endif
 
 
 
/* ------------------------------------------------------------------------------------
 * STEP 2: create /dev/secctl, set owner and permission, and consider constants
 * ------------------------------------------------------------------------------------
 *
 * > mknod /dev/secctl c 40 0		# you might need to change major,minor!
 * > chown root.secctl /dev/secctl
 * > chmod 660 /dev/secctl
 * > ls -al /dev/secctl
 *
 *    	"crw-rw---- 1 root secctl 40, 0 ... /dev/secctl"
 *
 *
 * On purpose, our SECCTL_DEVICE argument for open() is not configurable
 * by command line argument; We safely use a string-constant here.
 * If you ever change this, be sure to change or remove fprintf("%s", SECCTL_DEVICE )
 * in function safe_open_device() as well, since we do not want to re-print untrusted
 * user input via fprintf(%s).
 *
 * Be sure to set /dev/secctl owned by root.secctl with permission 660 (octal).
 * Why do we set owner=root : As the main part of this program does run with
 * UID=GID=<secctl> we do prevent any change to /dev/secctl (only the owner can
 * change a file).
 * Why do we set group=secctl : We open /dev/secctl with group <secctl> permission
 * in read/write mode. So we don't need to run this program as root anymore:
 *
 * 	Once /dev/secctl has been created with the above attributes,
 *	and /sbin/secctl has been installed, no more root privilege
 *	is needed to run it.
 *
 * Major and minor numbers need to coincide with those set in kernel LSM. 
 * Our default is <40,0> ,however this is not an official assignation.
 * So you better look out for any other device on your system that might
 * have this pair in use already.
 *
 * If you need to change the major number, then do change 
 * SECCTL_DEVICE_MAJOR to your new number.
 *
 * SECCTL_DEVICE_MINOR is only needed for comparison in safe_open_device()
 * and need not be changed if you change SECCTL_DEVICE_MAJOR
 *
 * These constants are defined in common.h, which we do include from the
 * KernelSpace LSM as well as from this UserSpace tool.
 *
 * If you need to change one of these constants, then do change it in common.h
 *
 *
 * #define	SECCTL_DEVICE			"/dev/secctl"
 *  
 * #define	SECCTL_DEVICE_MAJOR		40
 * #define	SECCTL_DEVICE_MINOR		0
 *
 *
 */


/* -----------------------------------------------------------------------
 * STEP 3: consider admissible characters for file-/object NAMEs in rules:
 *	(last "NAME" argument at the end of ruleline --->)
 * -----------------------------------------------------------------------
 * 
 * > secctl Nb. [accept|deny][+]  UID  [xrwa]  /mnt  I_Nb.  I_UID   [rdlbcsf]   NAME(!)
 *
 * 
 * We generally accept alphanumeric characters [a-zA-Z0-9] for NAME already.
 *
 * Further special characters are accepted only, if they are explicitely
 * allowed in SECCTL_FILENAME_ADMISSIBLE_SPECIAL_CHARS.
 *
 * As we do enforce this check in the KernelSpace LSM as well as in this
 * UserSpace tool, you need to apply any change in
 *
 *	common.h
 *
 * Currently we are very strict on admissible characters for NAME
 *
 *	#define SECCTL_FILENAME_ADMISSIBLE_SPECIAL_CHARS "_-.=+"
 *
 * These chars will be accepted additionally to the alphanumeric characters
 * by default.
 *
 * If you need to have additional chars like % or ' ' or '(' 
 * then you need to change or extend this constant in common.h.
 * Note that you likely have to change shell argument expansion also,
 * before invoking this program.
 * Placing the NAME inside "" or prepending "\" to any specical char 
 * on command line could help, but is NOT tested.
 *
 * Note: 
 * 	For mountpoint "/mnt" we are very much stricter: 
 *	Only alphanumeric characters (at least one) and '+' or '-'
 *      are allowed after '/'.
 *
 *	With one exception: Global Root '/' is OK also.
 * 
 * 	see sanity_check_path();
 *
 * (default: accept safe values as preset)
 */



/* -------------------------------------------------------------------
 * STEP 4: enable/disable strict ressource limits
 * -------------------------------------------------------------------
 *
 * we self-protect this program by
 *
 *	- reset env pointer,
 *	- check that 3 descriptors are opened (hope these are stdin, stdout, stderr)
 *	- deny late strace from another process,
 *	- depending on UID/GID at start, set (e)UID > 0 and (e)GID = SECCTL_GID
 *	  (we run only non-root then)
 *	- check sizeof(RTE)
 *
 * (default: enabled)
 *
 */
#define ENABLE_STRICT_RESSOURCE_LIMITS



/* -------------------------------------------------------------------
 * STEP 5: enable/disable usage of sha256/hmac for password mangling
 * -------------------------------------------------------------------
 * 
 * for
 * 	> secctl [lock|lockm|unlock] <password>
 *
 * if enabled, we invoke sha256(password) to decrease likelyhood of 
 * successful dictionary attacks. All the crypto functions are located in
 * "sha256.h", which is included here. One might consider these extensive
 * crypto stuff functions as huge overhead. However, if you implement
 * password like functions, it is better done right (hope so).
 *
 * if not enabled, we just use the password 'as is', possibly cut at 
 * the end to fit into RTE.d_iname[].
 * You need not include "sha256.h" then.
 *
 *
 * Note: do add to .bashrc : "export HISTFILESIZE=0"
 *  to avoid that an adversary can read passwords from ~/.bash_history
 *
 *
 * (default: enabled)
 *
 */
#define ENABLE_SEND_PASSWORD_THRU_SHA256


/* -------------------------------------------------------------------
 * STEP 6: compile
 * -------------------------------------------------------------------
 *
 * before compiling, enable or disable DEBUG() in common.h
 *
 *
 * For any security tool, we recommend to compile a static binary:
 *
 * > sh make.sh
 *
 *   OR
 *
 * > gcc -O2 -Wall -Wextra -Woverflow -Wformat-security -Wtype-limits \
 *	-Wpadded -Wpointer-arith -Wsign-compare -Wsign-conversion \
 *	-funsigned-char -fstack-protector -Wstack-protector -fpie \
 *	-static secctl.c -o secctl
 *
 * > strip secctl
 *
 */

 
/* -------------------------------------------------------------------
 * STEP 7: install and run
 * -------------------------------------------------------------------
 *
 * > su
 * > cp secctl /sbin
 * > chown root.secctl /sbin/secctl
 * > chmod 750 /sbin/secctl
 * > su secctl			<------- don't forget this !
 * > secctl
 *
 *
 *
 *
 * For special cases, you might consider setting /sbin/secctl SGID <secctl>
 * to enable _any_ user to run this program. As we do NOT recommend 
 * this setting, you have to enable ENABLE_ACCESS_FROM_ANY_USER then.
 * Normally, access to /dev/secctl should be reserved for an
 * administrative user with UID=0 or (recommended) UID/GID=<secctl>.
 *
 * > su
 * > cp secctl /sbin
 * > chown root.secctl /sbin/secctl
 * > chmod 2755 /sbin/secctl
 *
 * (default: not enabled)
 */
/* #define ENABLE_ACCESS_FROM_ANY_USER */


/*
 * ---------------------- END OF STEPS 0-7  --------------------------
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>			// for memset()
#include <ctype.h>			// for isdigit()
#include <ctype.h>			// for get[e]uid()
#include <linux/types.h>		// for __u8,16,32,64
#include <sys/types.h>			// for major(dev_t) .. and lstat()
#include <errno.h>
#include <sys/stat.h>			// for S_IFMT, S_IFREG, ... && for lstat()
#include <unistd.h>			// for lstat()
#include <fcntl.h>			// for O_RDWR
#include <sys/prctl.h>			// for prctl()
#include <sys/mman.h>			// for mlockall()
// #include <sys/time.h>
#include <sys/resource.h>		// for setrlimit()

#define SECCTL_USERSPACE
#include "common.h"
#include "sha256.h"


// For the sake of simplicity, we use a global var RTE of type RULE_TABLE_ENTRY;
// A new rule which is read from cmdline will be stored into this RTE, which
// is then transferred to the KernelSpace LSM via /dev/secctl.
// Anything that is received from KernelSpace LSM via read() will be stored
// into this global RTE as well.

RULE_TABLE_ENTRY	RTE;


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void usage_exit(void);
u8 parse_args( int argc, char **argv );
int parse_rule( char **argv );
int sha256_loop( u8 *array64, u32 loops );

u16 parse_number16bit( char *pstr, u32 base, int *rc );
u32 parse_number32bit( char *pstr, u32 base, int *rc );
u64 parse_number64bit( char *pstr, u32 base, int *rc );
int sanity_check_number( char *pstr, const u32 len, u32 base );
int sanity_check_number_dec( char *pstr, const u32 len );
int sanity_check_number_hex( char *pstr, const u32 len );
int sanity_check_number_oct( char *pstr, const u32 len );

int parse_diname( char *diname );

u32 parse_mountpoint_path( char *path, int *rc );
int sanity_check_path( char *path );

void sanitize_diname( char *diname, int diname_buf_len );
int sanity_check_diname( char *diname, int diname_buf_len, char subst );

int sanity_check_letters_only( char *str, u32 len );
int sanity_check_password( char *pass, u32 len );
int sanity_validate_size_of_RTE();
int safe_open_device();
int send_packet(int fd);
int send_packet_and_receive(int fd);
int receive_mounts(int fd);
void show_mount_entry(void);
int receive_rules(int fd);
void show_RTE(void);
int set_unpriv_UID_GID();
int set_unpriv_UID_GID_doublecheck();
int xsetrlimits(void);
int check_and_set_strict_ressource_limits(char **env);
int dispatch_cmd( u8 cmd, int fd );

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* for parse_number**bit() */

#define		BASE_DEC	1
#define		BASE_HEX	2
#define		BASE_OCT	4


// minimum & maximum length of password string (in number of characters from cmdline)

#define PW_MIN	12
#define PW_MAX	32

#if PW_MIN >= PW_MAX 
# error "PW_MIN >= PW_MAX"
#endif

#if PW_MIN < 12 
# error "PW_MIN should really be >= 12"
#endif

#if PW_MAX > 64 
# error "PW_MAX is very large, are you sure ?"
#endif


void usage_exit(void)
{
	printf(	"\nusage:\n\n"
		"secctl  Nb. [accept|deny][+]  UID  [xlrwa] /mnt  I_Nb.  I_UID   [rdlbcsf]   name\n"
		"secctl  0         accept     7001   x      /usr    *      *       d          *        (example1)\n"
		"secctl  1         accept+    7001   x      /usr  546456   0       r      sshd.static  (example2)\n"
		"secctl  2           deny+    7001   x      /usr    *      *       *          *        (example3)\n"
		"\n"
		"  Note: to avoid shell argument expansion of \"*\", do bash> export GLOBIGNORE=\\*\n"
		"        before calling secctl.\n"
		"\n"
		"------------------------------------------------------------------------------------------------\n"
		"secctl  %s\t\t\t# activate LSM\n"
		"secctl  %s\t\t\t# deactivate LSM\n" 
		"secctl  %s\t\t\t# set default policy: accept\n" 
		"secctl  %s\t\t\t# set default policy: deny\n" 
		"secctl  %s\t\t\t# show rules: trigger kernel LSM to call printk to syslog\n" 
		"secctl  %s\t\t\t# show rules: directly retrieve rules and call printf\n"
		"secctl  %s\t\t\t# clear rules\n" 
		"secctl  %s <passwd>\t\t# lock LSM with passwd (range:[a-zA-Z0-9]*[%2d-%2d], no spaces)\n" 
		"secctl  %s <passwd>\t\t#  < same as before, and deny kernel remount, umount, mount >\n" 
		"secctl  %s <passwd>\t\t# un-lock LSM with passwd\n", 
		MSG_LSM_ON,
		MSG_LSM_OFF,
		MSG_LSM_DEFAULT_POLICY_ACCEPT,
		MSG_LSM_DEFAULT_POLICY_DENY,
		MSG_LSM_PRINTK_RULES,
		MSG_LSM_SHOW_RULES,
		MSG_LSM_CLEAR_RULES,
		MSG_LSM_LOCK, PW_MIN, PW_MAX,
		MSG_LSM_LOCKM,
		MSG_LSM_UNLOCK );
		
	exit(0);
}

// parse cmdline
//
// if cmdline is a rule, then parse_rule() will be called, 
// and struct RTE.* will be filled with rule-data
//
// for any valid command, CMD_* will be returned
//
// rc:
//  either	0 if failure
//  or		>0 (CMD_*) if arg was successfully parsed

u8 parse_args( int argc, char **argv )
{
	char	pw[ PW_MAX ];
	char	*pstr;
	u8	*pdigest64;
	u8	rc;
	int	err;
	u32	len;


	DEBUG( fprintf(stderr,"DEBUG: argc == %d\n", argc ); )


	if( argc == 10 )		// maybe rule ?
	{
		// test&parse rule and fill global var RTE
			
		err = parse_rule( argv );
			
		if(err) return 0;
			
		return CMD_LSM_SET_RULE;
	}


	if( argc == 2 )
	{
		if( !strncmp( argv[1], MSG_LSM_ON, 		sizeof(MSG_LSM_ON) ) ) 			return CMD_LSM_ON;
		if( !strncmp( argv[1], MSG_LSM_OFF, 		sizeof(MSG_LSM_OFF) ) ) 		return CMD_LSM_OFF;
		if( !strncmp( argv[1], MSG_LSM_DEFAULT_POLICY_ACCEPT, 	sizeof(MSG_LSM_DEFAULT_POLICY_ACCEPT) ) ) 	return CMD_LSM_DEFAULT_POLICY_ACCEPT;
		if( !strncmp( argv[1], MSG_LSM_DEFAULT_POLICY_DENY,	sizeof(MSG_LSM_DEFAULT_POLICY_DENY) ) ) 	return CMD_LSM_DEFAULT_POLICY_DENY;
		if( !strncmp( argv[1], MSG_LSM_PRINTK_RULES, 	sizeof(MSG_LSM_PRINTK_RULES) ) ) 	return CMD_LSM_PRINTK_RULES;
		if( !strncmp( argv[1], MSG_LSM_SHOW_RULES, 	sizeof(MSG_LSM_SHOW_RULES) ) ) 		return CMD_LSM_SHOW_RULES;
		if( !strncmp( argv[1], MSG_LSM_CLEAR_RULES, 	sizeof(MSG_LSM_CLEAR_RULES) ) ) 	return CMD_LSM_CLEAR_RULES;
		
		DEBUG( if( !strncmp( argv[1], MSG_LSM_DEBUG_SIZE_TEST, sizeof(MSG_LSM_DEBUG_SIZE_TEST) ) ) 	return CMD_LSM_DEBUG_SIZE_TEST; )
		
		fprintf(stderr,"ERROR: 1st argument invalid; maybe missing 2nd arg ?\n");
		
		return 0;
	}
	
	if( argc == 3 )
	{	
		rc = 0;
	
		if( !strncmp( argv[1], MSG_LSM_LOCK, 	sizeof(MSG_LSM_LOCK) ) ) 	rc = CMD_LSM_LOCK;
		if( !strncmp( argv[1], MSG_LSM_LOCKM, 	sizeof(MSG_LSM_LOCKM) ) ) 	rc = CMD_LSM_LOCKM;
		if( !strncmp( argv[1], MSG_LSM_UNLOCK, 	sizeof(MSG_LSM_UNLOCK) ) )	rc = CMD_LSM_UNLOCK;
		
		if( !rc )
		{
			fprintf(stderr,"ERROR: [lock|lockm|unlock] expected, but no match !\n");
			
			return 0;
		}

		// ok: we have either "lock" or "lockm" or "unlock" cmd, 
		// now we do sanity check argv[2]:
		
		// general INPUT VALIDATION STRATEGY:
		//  a) safely check len of argv[#]
		//  b) copy max. number to local array
		//  c) check single characters against whitelist

		pstr = argv[2];
		
		// we need to see if given password is longer than allowed PW_MAX;
		//  so we check for PW_MAX+1 (we will copy maximum PW_MAX!)
		//
		
		len = (u32)strnlen( pstr, PW_MAX+1 );
		
		// len can be at most == PW_MAX+1 (we check for > PW_MAX in next line)
		
		if( (len < PW_MIN) || (len > PW_MAX) )
		{
			fprintf(stderr,"ERROR: [lock|lockm|unlock] <passwd> : expect %d..%d characters\n", PW_MIN, PW_MAX );
			return 0;
		}
		
		// now:   PW_MIN <= len(pw) <= PW_MAX
		
		memcpy( pw, pstr, len );		// Note: pw is not zero terminated!

		err = sanity_check_password( pw, len );
		
		if( err ) 
		{
			fprintf(stderr,"ERROR: [lock|lockm|unlock] <passwd> : expect alphanumeric characters only\n");
			return 0;
		}

#ifdef ENABLE_SEND_PASSWORD_THRU_SHA256

		// OK: pw did go thru our first sanity checks, 
		// now do process it with SHA256 / HMAC and SALT_1/2;
		// result will be 64 bytes digest; 40 bytes of digest are due to be stored into RTE.d_iname[]

		pdigest64 = sha256_password( (u8*) pw, len, &err );
		
		if( !pdigest64 ) return 0;
		
		/*
		 * now we use 40 bytes from the middle if pdigest64[] to be transfered
		 * to KernelSpace (1 packet RTE) later;
		 *
		 *     0...11    12...51    52...63
		 *      12        40          12
		 *
		 * 12+40 = 52 which leaves 12 bytes to the right in pdigest64[]
		 * 
		 * So 52 is max. number of bytes we can read starting from &pdigest64[12]
		 */

		BUILD_BUG_ON( SECCTL_DNAME_INLINE_LEN != 40 );


		memcpy( (u8*) RTE.d_iname, &pdigest64[12], SECCTL_DNAME_INLINE_LEN );


		/* 3rd param "&err" in function sha256_password() was just a dummy to
		 * convince the compiler to do the sanity clearance. Now we need to
		 * use "err" somehow... and do a dummy assignation to .diname_len
		 */
		 
		RTE.d_iname_len = (u8) err;


		/*
		 * digest is now in global var RTE.d_iname[] (40 bytes) 
		 *
		 ************************************************************************/
#else

		/************************************************************************
		 * don't use SHA256 ...
		 *
		 * we just copy maximum 40 bytes from pw[] into RTE.d_iname[]
		 *
		 */
		 
		 
		if( len >= SECCTL_DNAME_INLINE_LEN )
		{
			memcpy( (u8*)RTE.d_iname, (u8*)pw, SECCTL_DNAME_INLINE_LEN );
		}
		else
		{
			/* PW_MIN <= len < SECCTL_DNAME_INLINE_LEN */

			/* RTE was initially memset(,0,) in main() */
			
			memcpy( (u8*)RTE.d_iname, (u8*)pw, len );
			
		}
#endif


		/****************************************************************************************
		 * sanitize sensitive data 
		 *  	argv[2] does still contain the orignal password from cmdline;
		 *	note: on some systems, overwriting argv[] is seen as not proper behavior
		 */

		memset( argv[2], 0xFF, len );
	
		/****** sanitize end ********************************************************************/

		return rc;	// either ==CMD_LSM_LOCK or ==CMD_LSM_LOCKM or ==CMD_LSM_UNLOCK
	}




	fprintf(stderr,"ERROR: wrong number of arguments (argc=%d)!\n", argc );

	if( argc > 10 )
		fprintf(stderr," HINT: maybe \"*\" gets expanded by Shell? (try bash > export GLOBIGNORE=\\*)\n");
		
	return 0;
}



// called by parse_args()
//
// we do parse exactly _one_ rule here
//
// argc == 10 has been checked already
//
// for correct number parsing, we 1st do call sanity_check_number(),
// then rely on strtoul( char* , , 0 ):
// with param 0 to accept decimal, hex and oct values
//
// store result in global var RTE, which has been memset to 0 by calling function already
//
// note: we will re-validate all params in kernel lsm 
//
// rc:
//  either	-1 if failure
//  or		0  if rule was successfully parsed (into RTE)


int parse_rule( char **argv )
{
	char *rule;
	char *policy;
	char *uid;
	char *mask;
	char *devID;
	char *ino;
	char *iuid;
	char *mode;
	char *diname;
	
	int  	err;
	
	u16 	mode16;
	
	rule	= argv[1];	
	policy	= argv[2];
	uid	= argv[3];	
	mask	= argv[4];
	devID	= argv[5];	
	ino	= argv[6];	
	iuid	= argv[7];	
	mode	= argv[8];	
	diname	= argv[9];


	err = -1;
	
	if( isdigit2( *rule ) )
	{			
		RTE.rule_nb = parse_number16bit( rule, BASE_DEC|BASE_HEX, &err );

		// 0 <= RTE.rule_nb < RT_MAX

		if( RTE.rule_nb >= RT_MAX ) err = -1;
	}
	if(err) 
	{									
		fprintf(stderr,"ERROR: <rule_nb> out of range [0..%u]!\n", RT_MAX-1 );
		return -1;
	}

	if( ! strncmp( policy, "accept+", 7+1 ) ) 	// parse policy
	{
		RTE.bitfield |= POLICY_ACCEPT;
		RTE.bitfield |= LOGGING;
	}
	else
	if( ! strncmp( policy, "deny+", 5+1 ) )
	{
		RTE.bitfield |= POLICY_DENY;
		RTE.bitfield |= LOGGING;
	}
	else
	if( ! strncmp( policy, "accept", 6+1 ) )
	{
		RTE.bitfield |= POLICY_ACCEPT;
		
		// logging bit is already cleared by memset(0)
	}
	else
	if( ! strncmp( policy, "deny", 4+1 ) )
	{
		RTE.bitfield |= POLICY_DENY;
		
		// logging bit is already cleared by memset(0)
	}
	else
 	{
		fprintf(stderr,"ERROR: rule [%d]: <policy> out of range!\n", RTE.rule_nb);
		return -1;
	}



	if( *uid == '*' )				// parse uid
	{
		RTE.bitfield |= ANY_UID;

		if( *(uid+1) )
		{
			fprintf(stderr,"ERROR: rule [%d]: <uid> * must not be followed by any other char!\n", RTE.rule_nb);
			return -1;
		}
	}
	else
	{
		RTE.uid = parse_number32bit( uid, BASE_DEC|BASE_HEX, &err );

		if( err )
		{
			fprintf(stderr,"ERROR: rule [%d]: <uid> out of range!\n", RTE.rule_nb);
			return -1;
		}
		
	}
	

	switch( *mask )					// parse mask
	{
		case '*':	RTE.bitfield |= ANY_MASK;
		
				RTE.mask = '*';
				break;

		case 'x':	RTE.mask = 'x';
				break;

		case 'l':	RTE.mask = 'l';
				break;

		case 'r':	RTE.mask = 'r';
				break;

		case 'w':	RTE.mask = 'w';
				break;

		case 'a':	RTE.mask = 'a';
				break;

		default:	fprintf(stderr,"ERROR: rule [%d]: <mask> out of range!\n", RTE.rule_nb);
				return -1;
	}	
	if( *(mask+1) )
	{
		fprintf(stderr,"ERROR: rule [%d]: <mask> must be a single char!\n", RTE.rule_nb);
		return -1;
	}
	

	if( *devID == '*' )				// parse devID
	{
		fprintf(stderr,"ERROR: rule [%d]: <devID> : no wildcard allowed!\n", RTE.rule_nb);
		return -1;
	}			
	
	if( isdigit2( *devID ))
	{
		RTE.devID = parse_number32bit( devID, BASE_DEC|BASE_HEX, &err );
		
		if( err )
		{
			fprintf(stderr,"ERROR: rule [%d]: <devID> out of range!\n", RTE.rule_nb);
			return -1;
		}
	}
	else
	if( *devID == '/' )
	{
		RTE.devID = parse_mountpoint_path( devID, &err );
		
		if( err )
		{
			fprintf(stderr,"ERROR: invalid mountpoint or deviceID\n");
			return -1;
		}

		DEBUG( fprintf(stderr,"DEBUG: %u [%u:%u]\n", RTE.devID, major(RTE.devID), minor(RTE.devID) ); )
	}
	else
	{
		fprintf(stderr,"ERROR: rule [%d]: <devID> out of range, or no absolute path !\n", RTE.rule_nb);
		return -1;
	}
	
	
	
	if( *ino == '*' )				// parse ino
	{
		RTE.bitfield |= ANY_I_INO;

		if( *(ino+1) )
		{
			fprintf(stderr,"ERROR: rule [%d]: <i_ino> * must not be followed by any other char!\n", RTE.rule_nb);
			return -1;
		}
	}
	else
	{
		RTE.i_ino = parse_number64bit( ino, BASE_DEC|BASE_HEX, &err );
		
		if( err )
		{
			fprintf(stderr,"ERROR: rule [%d]: <i_ino> out of range\n", RTE.rule_nb);
			return -1;
		}
	}
	


	if( *iuid == '*' )				// parse uid of inode
	{
		RTE.bitfield |= ANY_I_UID;

		if( *(iuid+1) )
		{
			fprintf(stderr,"ERROR: rule [%d]: <i_uid> * must not be followed by any other char!\n", RTE.rule_nb);
			return -1;
		}
	}
	else
	{
		RTE.i_uid = parse_number32bit( iuid, BASE_DEC|BASE_HEX, &err );
		
		if( err )
		{
			fprintf(stderr,"ERROR: rule [%d]: <i_uid> out of range!\n", RTE.rule_nb);
			return -1;
		}
	}	


	/**************************************************************************
	 * see include/linux/stat.h
	 *   note: these are _OCTAL_ values !
	 
	 *	#define S_IFMT  00170000
	 *	#define S_IFSOCK 0140000  	<- s 
	 *	#define S_IFLNK	 0120000 	<- l 
	 *	#define S_IFREG  0100000  	<- r 
	 *	#define S_IFBLK  0060000  	<- b 
	 *	#define S_IFDIR  0040000  	<- d 
	 *	#define S_IFCHR  0020000  	<- c 
	 *	#define S_IFIFO  0010000  	<- f 
	 *	#define S_ISUID  0004000 	<- we do not care about this option
	 *	#define S_ISGID  0002000 	<- we do not care about this option
	 *	#define S_ISVTX  0001000 	<- we do not care about this option
	 *
	 * note: these are mutual exclusive values !
	 **************************************************************************/


	// for <mode> we accept one symbolic char out of [rdlbcsf],
	// or a number value like 0100000 (octal); can also be a hex value 0x..

	if( *mode == '0' )
	{
		// octal or hex number ? (we accept only octal)
		
		mode16 = parse_number16bit( mode, BASE_OCT, &err );

		if( err )
		{
			fprintf(stderr,"ERROR: rule [%d]: <i_mode> not an octal number!\n", RTE.rule_nb);
			return -1;
		}
					
		

		switch( mode16 )					// parse i_mode
		{
			case S_IFSOCK:
			case S_IFLNK:
			case S_IFREG:
			case S_IFBLK:
			case S_IFDIR:
			case S_IFCHR:
			case S_IFIFO:	RTE.i_mode = mode16;
			
					break;

			default:	fprintf(stderr,"ERROR: rule [%d]: <i_mode> invalid. Expect one of special octal values only!\n", RTE.rule_nb);
			
					return -1;
		}		
	}
	else
	{
		switch( *mode )					// parse i_mode
		{
			case '*':	RTE.bitfield |= ANY_I_MODE;	break;

			case 's':	RTE.i_mode = S_IFSOCK;	break;

			case 'l':	RTE.i_mode = S_IFLNK;	break;

			case 'r':	RTE.i_mode = S_IFREG;	break;

			case 'b':	RTE.i_mode = S_IFBLK;	break;

			case 'd':	RTE.i_mode = S_IFDIR;	break;

			case 'c':	RTE.i_mode = S_IFCHR;	break;

			case 'f':	RTE.i_mode = S_IFIFO;	break;

			default:	fprintf(stderr,"ERROR: rule [%d]: <i_mode> out of range [rdlbcsf*] (or octal number) !\n",RTE.rule_nb);
					return -1;

		}
		if( *(mode+1) )
		{
			fprintf(stderr,"ERROR: rule [%d]: <i_mode> must be a single char or in octal format!\n", RTE.rule_nb);
			return -1;
		}
	}
		
	
	if( *diname == '*' )				// parse & copy d_iname
	{
		RTE.bitfield |= ANY_D_INAME;

		if( *(diname+1) )
		{
			fprintf(stderr,"ERROR: rule [%d]: <filename> * must not be followed by any other char!\n", RTE.rule_nb);
			return -1;
		}

	}
	else
	{
		err = parse_diname( diname );
		
		if(err)
		{
			fprintf(stderr,"ERROR: rule [%d]: <filename> invalid!\n",RTE.rule_nb);
			return -1;
		}		
	}	

	
	RTE.bitfield |= USED;
	

	DEBUG( printf("DEBUG: new rule [%d] successfully parsed.\n", RTE.rule_nb ); )
	

	return 0;
}



// safely parse and convert string to number
//
// strategy for input validation:
//
// a) check len
// b) copy to local array
// c) check digits
// d) call strtoul()
// e) check for > U16_MAX
//

/* for (only) u16 (RTE.i_mode) we also accept numbers in octal base with maximum
 *
 * 	65535 or 0xFFFF or 0177777   <-> that is 7 chars maximum (would be 5 if we would only accept dec)
 *
 * note: 7 chars could also be 0xFFFFF or 9999999 then,
 * which outside range of u16, but inside range [0..U32_MAX];
 * 	so we use ((u32) strtoul()) for conversion, then check for > U16_MAX
 * 
 * for u32 and u64 we only accept dec or hex
 *
 * for all numbers, we only accept 0 or positive ("-" is not in whitelist and will be rejected)
 *
 *
 * 2nd param <base> can be logical OR combination of ( BASE_DEC | BASE_HEX | BASE_OCT )
 *  that is: the calling function will determine which base(s) is(are) acceptable
 */
 
#define MAX_U16_STRLEN	7

#define MAX_U32_STRLEN	10
#define MAX_U64_STRLEN	20

// *rc: (3rd param)
//  either	-1 unacceptable char found
//  or		0  all acceptable chars (OK)


u16 parse_number16bit( char *pstr, u32 base, int *rc )
{
	char 	tmpstr[ MAX_U16_STRLEN + 1 ];
	int	err;
	u32	len;
	u16	nb16;
	u32	nb32;
	
	*rc = -1;

	if( !pstr) return 0;				// error.

	strncpy( tmpstr, pstr, MAX_U16_STRLEN + 1 );

	len = (u32) strnlen( tmpstr, MAX_U16_STRLEN + 1 );
	

	if( len < 1 ) return 0;				// error: pstr too short
	if( len > MAX_U16_STRLEN ) return 0;		// error: pstr longer than MAX_U16_STRLEN
	

	err = sanity_check_number( tmpstr, len, base );	// check number and base

	if(err)	return 0;				// error: pstr does contain invalid characters

	errno = 0;

	nb32 = (u32) strtoul( tmpstr, NULL,  0);

	if(errno) return 0;				// error: strtoul() failed.
	
	if( nb32 > U16_MAX ) return 0;			// error: number is > 65535
	
	nb16 = (u16) nb32;
	
	*rc = 0;
	
	return nb16;
}


// *rc: (3rd param)
//  either	-1 unacceptable char found
//  or		0  all acceptable chars (OK)

u32 parse_number32bit( char *pstr, u32 base, int *rc )
{
	char 	tmpstr[ MAX_U32_STRLEN + 1 ];
	int	err;
	u32	len;
	u32	nb32;
	u64	nb64;
	
	*rc = -1;

	if( !pstr) return 0;				// error.

	strncpy( tmpstr, pstr, MAX_U32_STRLEN + 1 );

	len = (u32) strnlen( tmpstr, MAX_U32_STRLEN + 1 );
	

	if( len < 1 ) return 0;				// error: pstr too short
	if( len > MAX_U32_STRLEN ) return 0;		// error: pstr longer than MAX_U32_STRLEN

		
	err = sanity_check_number( tmpstr, len, base );	// check number and base
	
	if(err)	return 0;				// error: pstr does contain invalid characters
	
	errno = 0;
		
	nb64 = (u64) strtoull( tmpstr, NULL, 0);
	
	if(errno) return 0;				// error: strtoul() failed.
	
	if( nb64 > U32_MAX ) return 0;			// error: although maximum 10 digits, our number is > 4294967295
	
	nb32 = (u32) nb64;
	
	*rc = 0;
	
	return nb32;
}


// *rc: (3rd param)
//  either	-1 unacceptable char found
//  or		0  all acceptable chars (OK)

u64 parse_number64bit( char *pstr, u32 base, int *rc )
{
	char 	tmpstr[ MAX_U64_STRLEN + 1 ];
	int	err;
	u32	len;
	u64	nb64;
	
	*rc = -1;

	if( !pstr) return 0;				// error.

	strncpy( tmpstr, pstr, MAX_U64_STRLEN + 1 );

	len = (u32) strnlen( tmpstr, MAX_U64_STRLEN + 1 );
	

	if( len < 1 ) return 0;				// error: pstr too short
	if( len > MAX_U64_STRLEN ) return 0;		// error: pstr longer than MAX_U64_STRLEN
	
		
	err = sanity_check_number( tmpstr, len, base );	// check number and base
	
	if(err)	return 0;				// error: pstr does contain invalid characters
	
	errno = 0;
		
	nb64 = (u64) strtoull( tmpstr, NULL, 0);
	
	if(errno) return 0;				// error: strtoull() failed.
	
	// cannot check for overflow if we have 20 digits, number could be greater than MAX_U64 thou;
	// we would have to check the string then.. ;
	// so far we do rely on errno==ERANGE from strtoull() for overflow
	
	*rc = 0;
	
	return nb64;
}

// e.g. base == BASE_DEC | BASE_OCT
//  then we check first for decimal number; 
//  if failure, then we check second for octal number; 
//
// rc:
//  either	-1 unacceptable char found; or error with <base>
//  or		0  all acceptable chars (OK)

int sanity_check_number( char *pstr, const u32 len, u32 base )
{
	int err;

	if( !base ) return -1;						// error.
	
	if( (base & (BASE_DEC|BASE_HEX|BASE_OCT)) == 0 ) return -1;	// error: at least one <base> must be given
	
	
	if( base & BASE_DEC )
	{
		err = sanity_check_number_dec( pstr, len );
		
		if( !err ) return 0;
	}
	
	if( base & BASE_HEX )
	{
		err = sanity_check_number_hex( pstr, len );
		
		if( !err ) return 0;
	}
	
	
	if( base & BASE_OCT )
	{
		err = sanity_check_number_oct( pstr, len );
		
		if( !err ) return 0;
	}
	
	return -1;							// error.
}


// rc:
//  either	-1 unacceptable char found
//  or		0  all acceptable chars

int sanity_check_number_dec( char *pstr, const u32 len )
{
	u32 i;
	char c;
	
	if( (len < 1) || (len > MAX_U64_STRLEN) ) return -1;


	if( len==1 )
	{
		// the only exception where a decimal number
		// may start with 0, is zero itself
		
		if( pstr[0] == '0' ) return 0;
	}


	// first digit must be in range [1..9]

	c = pstr[0];
	
	if( c < '1' || c > '9' ) return -1; 


	// following digits must be in range [0..9]

	for( i=1; i<len; i++ )
	{
		c = pstr[i];

		if( isdigit2(c) ) continue;
		
		return -1;
	}

	return 0;
}

// rc:
//  either	-1 unacceptable char found
//  or		0  all acceptable chars

int sanity_check_number_hex( char *pstr, const u32 len )
{
	u32 i;
	char c;
	
	/* "0x1" <- minimum length is 3 */
	
	if( (len < 3) || (len > MAX_U64_STRLEN) ) return -1;

	if( pstr[0] != '0') return -1;
	if( pstr[1] != 'x') return -1;
	

	for( i=2; i<len; i++ )
	{
		c = pstr[i];

		if( isdigit2(c) ) continue;
		
		if( (c >= 'a') && (c <= 'f') ) continue;
		
		if( (c >= 'A') && (c <= 'F') ) continue;
		
		
		return -1;
	}

	return 0;
}

// rc:
//  either	-1 unacceptable char found
//  or		0  all acceptable chars

int sanity_check_number_oct( char *pstr, const u32 len )
{
	u32 i;
	char c;
	
	if( (len < 1) || (len > MAX_U64_STRLEN) ) return -1;


	if( pstr[0] != '0') return -1;

	for( i=1; i<len; i++ )
	{
		c = pstr[i];

		if( isdigit2(c) ) continue;
		
		return -1;
	}
	
	return 0;
}


		


// max. length of .diname is <SECCTL_DNAME_INLINE_LEN - 1> since we force zero term.
// 
// rc:
//  either	-1 unacceptable char found
//  or		0  all acceptable chars (OK)

int parse_diname( char *diname )
{	
	char	tmpstr[ SECCTL_DNAME_INLINE_LEN ];
	u32 	len;
	int	err;
	
	
	if( !diname ) return -1;

	memset( tmpstr, 0, SECCTL_DNAME_INLINE_LEN );
	
	strncpy( tmpstr, diname, SECCTL_DNAME_INLINE_LEN );
	
	len = (u32) strnlen( tmpstr, SECCTL_DNAME_INLINE_LEN );

	if( len < 1 ) return -1;	
	
	if( len > (SECCTL_DNAME_INLINE_LEN-1) )
	{
		fprintf(stderr,"ERROR: <filename> len out of range [1..%u] !\n", SECCTL_DNAME_INLINE_LEN - 1 );
		return -1;
	}
	
	// now: 1 <= len <= (SECCTL_DNAME_INLINE_LEN-1)
	
	tmpstr[ SECCTL_DNAME_INLINE_LEN-1 ] = 0;				// should not be needed
	tmpstr[ len ] = 0;							// should already be set
	

	err = sanity_check_diname( tmpstr, SECCTL_DNAME_INLINE_LEN, 0x0 );	// note: 2nd param is length of buffer
		
	if(err)
	{
		fprintf(stderr,"ERROR: <filename> has invalid chars!\n");
		return -1;
	}


	memcpy( RTE.d_iname, (u8*) tmpstr, SECCTL_DNAME_INLINE_LEN );
	
	return 0;
}




// sanitize diname[] before printing via printf("%s", d_iname )
//  called from show_RTE()
//
// when we receive a logged RTE packet from kernel,
// then we have a .d_iname[] which comes from UserSpace and clearly should be 
// sanitized by the kernel already - but can we depend on it ?
// In particular, if diname would contain format specifiers like '%' !?
// So we better do a very strict sanitize for ourselves.
//
// arg #diname_buf_len is length of buffer, not length of diname
//

void sanitize_diname( char *diname, int diname_buf_len )
{
	(void) sanity_check_diname( diname, diname_buf_len, '.' );
}


//
// *rc: (2nd param!)
//
//  either	-1 unacceptable char found; invalid path
//  or		0  all acceptable chars; path OK

u32 parse_mountpoint_path( char *path, int *rc )
{
	struct stat	s;
	int		err;
	
	
	
	*rc = -1;


	err = sanity_check_path( path );

	if( err )
	{
		fprintf(stderr,"ERROR: mountpoint: invalid path!\n");
		return 0;
	}
		

	// we call lstat vs. stat to make sure that <path> is _not_ a link
	// (from the manpage: "if path is a symbolic link, then the link itself
	//  is stat-ed, not the file that it refers to.")
	
	err = lstat( path, &s );

	if( err )
	{
		fprintf(stderr,"ERROR: mountpoint: cannot access. lstat() failed!\n");
		return 0;	/* *rc = -1; */
	}


        if( S_ISLNK( s.st_mode ) )
	{
		fprintf(stderr,"ERROR: mointpoint: symlink not allowed!\n");
		return 0;	/* *rc = -1; */
	}

        if( ! S_ISDIR( s.st_mode ) )
	{
		fprintf(stderr,"ERROR: mointpoint: must be directory!\n");
		return 0;	/* *rc = -1; */
	}

	*rc = 0;

	return s.st_dev;	// "ID of device containing file" (from the manpage)	<-> this will be our deviceID
}



// check mountpoint path for valid chars
//
// positive cases:
//
// case1:	'/'
// case2:	'/sys'
// case3:	'/data[/part2]*'
//
// path must start with '/' and must not end with '/'
//
// between any two consecutive slashes we only accept
//	1) alphanumeric characters
//	2) '+' or '-'
//
// rc:
//  either	-1 unacceptable char found; path not OK
//  or		0  all acceptable chars, path OK
//

// should we use PATH_MAX as length delimiter ? 
//  (we see #define PATH_MAX 4096 in <linux/limits.h>,
//   but this seems really a bit too long for us, since
//   we only have mountpoint paths here, which should be
//   really more at the beginning of a filesystem tree,
//   and very much shorter then)

#define MAX_MOUNTPOINT_PATH_LEN		64

int sanity_check_path( char *path )
{
	char	tmpstr[ MAX_MOUNTPOINT_PATH_LEN + 1 ];
	char	c;
	u32	len;
	u32	i;
	
	if(!path) return -1;
	
	strncpy( tmpstr, path, MAX_MOUNTPOINT_PATH_LEN + 1 );

	len = (u32) strnlen( tmpstr, MAX_MOUNTPOINT_PATH_LEN + 1 );

	if( len < 1 ) return -1;					// error: too short
	if( len > MAX_MOUNTPOINT_PATH_LEN )
	{
		fprintf(stderr,"ERROR: mountpoint: path too long (expect [1..%u] characters !)\n", MAX_MOUNTPOINT_PATH_LEN );
		return -1;						// error: too long
	}
	
	tmpstr[len] = 0;
	tmpstr[MAX_MOUNTPOINT_PATH_LEN] = 0;				// should not be needed
	
	if( tmpstr[0] != '/') 
	{
		fprintf(stderr,"ERROR: mountpoint: must be absolute path !\n");
		return -1;						// error.
	}

	if( len == 1 ) return 0;					// case 1; leading '/' just checked.


	if( tmpstr[len-1] == '/')					// error: we do not allow trailing '/'
	{
		fprintf(stderr,"ERROR: mountpoint: no slash at the end of path allowed !\n");
		return -1;						// error.
	}
	
	
	//
	//	check for valid chars: [/][0-9][a-z][A-Z][+][-]
	//
		
	for( i=0; i<len; i++)
	{
		c = tmpstr[i];
		
		if( c == '/' ) continue;
		
		if( isalnum2( c )  ) continue;
		
		if( c == '+' || c == '-' ) continue;

		fprintf(stderr,"ERROR: mountpoint: invalid characters (we accept alphanumeric or '+' or '-' !)\n");
		
		return -1;						// error: invalid char at tmpstr[i]
	}

	
	for( i=1; i<len; i++)
	{
		if( (tmpstr[i-1] == '/') && (tmpstr[i] == '/') )
		{
			fprintf(stderr,"ERROR: mountpoint: no double slash allowed !\n");
			return -1;					// error.
		}
	}

	return 0;
}



// rc:
//  either	-1 unacceptable char found
//  or		0  all acceptable chars

int sanity_check_letters_only( char *str, u32 len )
{
	u32 i;
	char c;

	for( i=0; i < len; i++ )
	{
		c = str[i];

		if( isletter2(c) ) continue;
		
		return -1;
	}
	
	return 0;
}

// all characters must be alphanumeric
//
// rc:
//  either	-1 unacceptable char found
//  or		0  all acceptable chars

int sanity_check_password( char *pass, u32 len )
{
	u32 i;
	char c;

	for( i=0; i < len; i++ )
	{
		c = pass[i];

		if( isalnum2(c) ) continue;
		
		return -1;
	}
	
	return 0;
}



/*********************************************************************************
 * This was our original check that RTE has the right size (at runtime).
 *
 * Meanwhile we have a compile-time check via
 *  BUILD_BUG_ON( sizeof(RULE_TABLE_ENTRY) != (RULE_TABLE_ENTRY_EXPECTED_SIZE ) )
 * which is called from main().
 *
 * We still call this function at runtime as a double-check.
 */

// rc:
//
//	either 	 0 if OK
//	or 	-1 if error

int sanity_validate_size_of_RTE()
{
	u32 size;
	
	
	size = (u32)sizeof( RULE_TABLE_ENTRY );
	

	///////////////////////////////////////////////
	// check that RTE size is as expected;
	// although we do not strictly rely on it, this
	// better needs an explanation!
	// anycase we expect <size> at least multiple of 4
	
	if( size != RULE_TABLE_ENTRY_EXPECTED_SIZE )
	{
		fprintf(stderr,"secctl: init() ERROR: sizeof(RTE) != %u\n", RULE_TABLE_ENTRY_EXPECTED_SIZE );
		return -1;
	}

	return 0;
}



// called by main()
//
// We open(SECCTL_DEVICE) in write-mode being UID/GID <secctl>.
// So we better check that it is most probably our character device,
// not e.g. a subverted symlink; For that, our call sequence is:
//
//	lstat( &s1) ...
//	open() ...
//	fstat( &s2) ...
//	compare s1 "==" s2 (most relevant items, times may differ)
//
// Note: SECCTL_DEVICE is defined as constant; 
//
// The calling function is responsible to close(fd) later on
//
// rc:
//
//	either 	 >0 file descriptor from open(SECCTL_DEVICE)
//	or 	-1 if error
//

int safe_open_device()
{
	int fd;
	int err;
	struct stat s1, s2;


	// we call lstat vs. stat to make sure that SECCTL_DEVICE is _not_ a link
	// (from the manpage: "if path is a symbolic link, then the link itself
	//  is stat-ed, not the file that it refers to.")
	
	err = lstat( SECCTL_DEVICE, &s1 );
	
	if( err )
	{
		fprintf(stderr,"ERROR: lstat( %s ) FAILED", SECCTL_DEVICE );
		
		perror("");
		
		return -1;
	}

	// we test for strict equality

        if( ! (s1.st_mode==(S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)) )
	{
		fprintf(stderr,"ERROR: ( %s ): expect character device with permission 0660 !\n", SECCTL_DEVICE );

		return -1;
	}
	
        if( (s1.st_uid != 0)||(s1.st_gid != SECCTL_GID) )
	{
		fprintf(stderr,"ERROR: ( %s ): expect device to be owned by root.secctl !\n", SECCTL_DEVICE );

		return -1;
	}

	if( ( major(s1.st_rdev) != SECCTL_DEVICE_MAJOR )||
	    ( minor(s1.st_rdev) != SECCTL_DEVICE_MINOR ) )
	{
		fprintf(stderr,"ERROR: ( %s ): expect device with major,minor : %u, %u !\n", SECCTL_DEVICE, SECCTL_DEVICE_MAJOR, SECCTL_DEVICE_MINOR );
		
		return -1;
	}
	
        if( ( s1.st_size > 0 )||( s1.st_nlink > 1 ) )
	{
		// this really should not be

		return -1;
	}

	
	// still here we have a race condition TOCTOU ---
	// That's why we re-call stat() after open() below, and do purposely not give
	// O_CREAT and O_TRUNC as args for open() to prevent overwriting
	// a subverted <device> when just opening it.

	fd = open( SECCTL_DEVICE, O_RDWR | O_NOFOLLOW );
	
	if( fd < 0 )
	{
		fprintf(stderr,"ERROR: open( %s ) FAILED", SECCTL_DEVICE );
		
		perror("");
		
		return -1;
	}

	// 0,1,2 should really be reserved for stdin, stdout, stderr.
	// Although this is not a strict general requirement, we cannot see
	// why in this context our #fd should get one of these values.

	if( (fd == 0) || (fd == 1) || (fd == 2) )
	{
		fprintf(stderr,"ERROR: open( %s ) FAILED: wrong descriptor!", SECCTL_DEVICE );
		
		return -1;
	}


	err = fstat( fd, &s2 );

	if( err )
	{
		close(fd);
	
		fprintf(stderr,"ERROR: fstat( %s ) FAILED", SECCTL_DEVICE );
		
		perror("");
		
		return -1;
	}
	
	// check that s1 from lstat() an s2 from fstat() come most probably from same file
	//
	// (Still we have a small race-condition here, if the kernel does re-use inode-numbers
	//  too quickly again after unlink. At least, the new device (*) file should fulfill our
	//  expected attributes then)
	// (*) could be quickly re-created between lstat() and fstat()
	
	err = 0;
	
	if( s1.st_ino  != s2.st_ino ) err = -1;
	if( s1.st_size != s2.st_size ) err = -1;
        if( s1.st_uid  != s2.st_uid ) err = -1;
        if( s1.st_gid  != s2.st_gid ) err = -1;
	if( s1.st_mode != s2.st_mode ) err = -1;
	if( s1.st_nlink != s2.st_nlink ) err = -1;
	if( major(s1.st_rdev) != major(s2.st_rdev) ) err = -1;
	if( minor(s1.st_rdev) != minor(s2.st_rdev) ) err = -1;
	
	if( err )
	{
		close(fd);
		return -1;
	}
	
	
	// DEBUG( fprintf(stderr,"DEBUG: stat.st_dev ( %s ) = %u %u\n", SECCTL_DEVICE, major(s1.st_dev), minor(s1.st_dev) ); )	
	// DEBUG( fprintf(stderr,"DEBUG: stat.st_rdev ( %s ) = %u %u\n", SECCTL_DEVICE, major(s1.st_rdev), minor(s1.st_rdev) ); )	
	// DEBUG( fprintf(stderr,"DEBUG: stat.st_uid ( %s ) = %X\n", SECCTL_DEVICE, s1.st_uid ); )	
	// DEBUG( fprintf(stderr,"DEBUG: stat.st_uid ( %s ) = %X\n", SECCTL_DEVICE, s1.st_uid ); )	
	// DEBUG( fprintf(stderr,"DEBUG: stat.st_mode( %s ) = o%o (we expect o%o)\n", SECCTL_DEVICE, s1.st_mode, S_IFCHR|S_IRUSR|S_IWUSR ); )	
	
	
	return fd;
}




// called by dispatch_cmd()
//
// param <fd> is from open(SECCTL_DEVICE)
//
// rc:
//
//	either 	 0 if OK
//	or 	-1 if error

int send_packet(int fd)
{
	int nbytes;
	
	
	(void) secctl_calc_RTE_checksum( &RTE );

	errno = 0;
	
	nbytes = (int)write( fd, &RTE, sizeof( RULE_TABLE_ENTRY ) );

	if( errno || (nbytes < 0))
	{
		if( (RTE.cmd == CMD_LSM_SET_RULE)||
		    (RTE.cmd == CMD_LSM_DEFAULT_POLICY_ACCEPT)||
		    (RTE.cmd == CMD_LSM_DEFAULT_POLICY_DENY)||
		    (RTE.cmd == CMD_LSM_CLEAR_RULES) )
		{
			if( nbytes == -EPERM )
			{
				fprintf(stderr,"Please call\n\t>secctl off\nbefore changing rules or policy!\n");
			}
			if( nbytes == -EINVAL )
			{
				fprintf(stderr,"Parameter not correct!\n");
			}
			
			fprintf(stderr,"See also syslog for error information.\n");
		}
		
		
		return -1;
	}
	
	if( nbytes != (int)sizeof( RULE_TABLE_ENTRY ) )
	{
		fprintf(stderr,"ERROR: write( %s ): wrote %d of %d bytes: ", SECCTL_DEVICE, nbytes, (int)sizeof( RULE_TABLE_ENTRY ));
		
		perror("");

		return -1;
	}
	
	DEBUG( fprintf(stderr,"DEBUG: send_packet: write( %s ): wrote %d of %d bytes.\n", SECCTL_DEVICE, nbytes, (int)sizeof( RULE_TABLE_ENTRY )); )
	
	return 0;
}


// called by dispatch_cmd()
//
// param <fd> is from open(SECCTL_DEVICE)
//
// rc:
//
//	either 	 0 if OK
//	or 	-1 if error

int send_packet_and_receive(int fd)
{
	int nbytes;
	int err;

	
	RTE.checksum = secctl_calc_RTE_checksum( &RTE );
	
	errno = 0;
	
	nbytes = (int)write( fd, &RTE, sizeof( RULE_TABLE_ENTRY ) );

	if( errno || (nbytes < 0))
	{
		perror("send_packet_and_receive()");
		
		return -1;
	}
	
	
	if( nbytes != (int)sizeof( RULE_TABLE_ENTRY ) )
	{
		fprintf(stderr,"ERROR: write( %s ) wrote %d of %d bytes.\n", SECCTL_DEVICE, nbytes, (int)sizeof( RULE_TABLE_ENTRY ));
		
		return -1;
	}

	DEBUG( fprintf(stderr,"DEBUG: send_packet_and_receive: write( %s ): wrote %d of %d bytes.\n", SECCTL_DEVICE, nbytes, (int)sizeof( RULE_TABLE_ENTRY )); )
	
	switch( RTE.cmd )
	{

		case CMD_LSM_SHOW_RULES:	err = receive_rules( fd );
		
						if(err) 
						{
							fprintf(stderr,"receive_rules() FAILED\n");

							return -1;
						}
						
						break;

		/* we used to have more debug case statements here,
		 * that's why we are having a switch statement for just one remaining case;
		 */
				
	}

	return 0;
}


// called by send_packet_and_receive()
//
// RTE.cmd (==CMD_LSM_SHOW_RULES)
//  has been set by calling function
//
// now we expect to read all entries from RT[] (rule table)
//
// -------------------------------------------------------------------
// if there are no rules in kernel RT[], then read() will simply return nothing;
// 					CHECK THIS: maybe we need check nbytes for == 0 <<<<<<<<<<<<<<<<<<<<<<<<---------------
// rc:
//
//	either 	 0 if OK
//	or 	-1 if error

int receive_rules( int fd )
{
	
	int nbytes;
	int sumbytes;
	int safety;
	int nentries;
	u32 checksum;
	
	nbytes = 0;
	sumbytes = 0;
	safety = 0;
	nentries = 0;

	// 
	// printf("secctl: --- show rules:\n");
	// printf(" rule | policy | uid | mask | devID |   i_ino   | i_uid | i_mode | d_iname   [account]\n");
	//
	// Note: we refrain from printing a header at top of the rules, since this would complicate
	//	grepping in the results ... on the other hand: a header explaining the entries would 
	//	give a little help to the reader;
	
	
	do
	{
		errno = 0;
		
		nbytes = (int)read( fd, &RTE, sizeof( RULE_TABLE_ENTRY ) );
		
		if( errno || (nbytes < 0))
		{
			perror("receive_rules()");
			
			return -1;
		}
		
		DEBUG( fprintf(stderr,"receive_rules(): fread() -> %d bytes.\n", nbytes ); )
		
		if( nbytes != (int)sizeof( RULE_TABLE_ENTRY ) )
		{
			if( sumbytes > 0 ) break;		// at least one previous read() was successful already

			// if we are here, then
			// the very first read() did fail somehow; 
			// could be that there are simply not rules in RT[] then

			DEBUG( fprintf(stderr,"receive_rules(): 1st read() failed: only %d bytes.\n", nbytes ); );

			break;					// silently return of there are no rules.
		}

		// re-calc integrity .checksum first:

		checksum = RTE.checksum;

		if( checksum != secctl_calc_RTE_checksum( &RTE ) )
		{
			fprintf(stderr,"receive_rules(): checksum FAILED for entry %d !\n",  nentries );
			
			continue;
		}

		sumbytes += nbytes;

		DEBUG( fprintf(stderr,"DEBUG: receive_rules: round %d: did read %d bytes (sumbytes=%d)\n", safety, nbytes, sumbytes); )
		
		nentries++;
		
		// print rule entry ...
		
		show_RTE();			// print RTE
		
	}
	while( (safety++) < RT_MAX );

	DEBUG( fprintf(stderr,"DEBUG: receive_rules: END: did read %d sumbytes for %d entries in RT[]\n", sumbytes, nentries ); )

	return 0;
}




// called by receive_rules()
//
// print RULE_TABLE entries

void show_RTE(void)
{
	char *oops = "Oops";
	
	char *policy;
	char *accept_log = "accept+";
	char *accept     = "accept";
	char *deny_log   = "deny+";
	char *deny       = "deny";


	if( ! RTE_USED )
	{
		fprintf(stderr,"RULE INVALID\n");
		return;
	}

	// ---------------------------------------------

	printf("[%3d]\t", RTE.rule_nb );

	// ---------------------------------------------

	// safely initialize <policy>:
	// oops could be "exception case" - see kernel lsm
	// for neither ACCEPT or DENY bit set
	//
	// we also print safely oops if both ACCEPT or DENY bits are set
	// (this should not happen normally; at least we see it here)
	
	policy = oops;		
	
	if( ( RTE_POLICY_ACCEPT ) && ( ! RTE_POLICY_DENY ) )
	{
		 if( RTE_LOGGING ) policy = accept_log;
		 else policy = accept;
	}
	if( ( RTE_POLICY_DENY   ) && ( ! RTE_POLICY_ACCEPT ) )
	{
		 if( RTE_LOGGING ) policy = deny_log;
		 else policy = deny;
	}
	
	printf("%.7s\t", policy );
	
	// ---------------------------------------------

	if( RTE_ANY_ALL )	
	{
		printf("*\t*\t0x%X\t*\t*\t*\t*\t[%u] [ANY_ALL]\n", (u32)RTE.devID, RTE.account  );
		
		return;		// all printed at once. can return.
	}

	// ---------------------------------------------

	if( RTE_ANY_UID )	
		printf("*\t");
	else
		printf("%u\t", (u32)RTE.uid );

	// ---------------------------------------------

	if( RTE_ANY_MASK )
		printf("*\t");
	else
	{
		// is one of [xlrwa] when we print from RT[]
		
		switch( RTE.mask )
		{
			case 'x':
			case 'l':
			case 'r':
			case 'w':
			case 'a':	printf("%c\t", (char)RTE.mask );
					break;

			default:	printf("0x%X\t", RTE.mask );
		}
	}

	// ---------------------------------------------

	printf("0x%X\t", (u32)RTE.devID );

	// ---------------------------------------------

	if( RTE_ANY_I_INO )
		printf("*\t");
	else
		printf("%llu\t", (u64)RTE.i_ino );

	// ---------------------------------------------

	if( RTE_ANY_I_UID )
		printf("*\t");
	else
		printf("%u\t", (u32)RTE.i_uid);

	// ---------------------------------------------

	if( RTE_ANY_I_MODE )
		printf("*\t");
	else
		printf("0%o\t", (u32)RTE.i_mode );

	// ---------------------------------------------

	if( RTE_ANY_D_INAME )
		printf("*           \t");
	else
	{
		if( RTE.d_iname[0] )
		{
			RTE.d_iname[ SECCTL_DNAME_INLINE_LEN - 1 ] = 0;

			// When we print from our Kernel RT[] rule table,
			// this might be considered trusted input, since we did 
			// sanity_check previously when rules were loaded
			// into the kernel. However, it is a long way since.
			// So we better do sanity checks again.
						
			sanitize_diname( RTE.d_iname, SECCTL_DNAME_INLINE_LEN );
		
			// precision "*" specifier for max. string len, given as
			// argument (SECCTL_DNAME_INLINE_LEN - 1) before string pointer
			
			printf("%-12.*s\t", SECCTL_DNAME_INLINE_LEN - 1, RTE.d_iname );
		}
		else
		{
			printf("<empty>     \t");
		}
	}

	// ---------------------------------------------
	// is <counter> when we print from RT[]
	
	printf("[%u]\n", RTE.account );
}



// called by check_and_set_strict_ressource_limits()
//
// Note: have a look also at function
//	set_unpriv_UID_GID_doublecheck(),
//	where we check whether we were successful here.
//
// rc:
//
//	either 	 0 if OK
//	or 	-1 if error
//

int set_unpriv_UID_GID()
{	
	int err;


	// CASE 1: we are started with (e)UID==0
	//	regardless GID, which could already be set to SECCTL_GID 
	// 
	// then we drop root privilege and set UID/GID to <secctl>
	//
		
	if( ( geteuid() == 0 )||( getuid() == 0 ) )
	{

		// drop UID root privileges before safe_open_device(), and
		// before parsing command line arguments

		// We trust that this process _cannot_ regain UID root privileges by calling setuid(0)
		//
		// From manpage of setuid( _uid_ )
		//  "If the user is root or the program is set-user-ID-root, special care must be taken.
		//   The setuid() function checks the effective user ID of the caller and if it is the 
		//   superuser, all process-related user ID's are set to _uid_. After this has occurred,
		//   it is impossible for the program to regain root privileges."
		//

		err = setgid( SECCTL_GID );	/* do setgid() _before_ setuid() ! */

		if( err )
		{
			perror("ERROR: setgid() to unpriv. GID FAILED");
			return -1;
		}


		err = setuid( SECCTL_UID );

		if( err )
		{
			perror("ERROR: setuid() to unpriv. UID FAILED");
			return -1;
		}
		
		return 0;
	}
	
	//
	// CASE 2: we are started with (e)UID = (e)GID = <secctl>
	// 	This is a normal login/su to <secctl>
	//
	// then anything is fine, we need not change anything.
	//
	
	if( (getuid() == SECCTL_UID) && ( geteuid() == SECCTL_UID ) &&
	    (getgid() == SECCTL_GID) && ( getegid() == SECCTL_GID ) )
	{
		return 0;
	}
	
#ifdef ENABLE_ACCESS_FROM_ANY_USER

	//
	// CASE 3: we are started with SGID (mode 2755) <secctl> from another UID 
	// 	(another UID can only be >0, since we checked ==0 in CASE 1 already)
	//
	//  (this is not recommended, so this is not enabled by default!)
	//
	
	if( getegid() == SECCTL_GID )
	{
		if( getgid() != SECCTL_GID )
		{
			if( (getuid() > 0) && (geteuid()>0 ) ) return 0;
		}
	}

#endif


	return -1;
}
	

// called by check_and_set_strict_ressource_limits()
//
// re-check whether we were successful in function set_unpriv_UID_GID()
//
// rc:
//
//	either 	 0 if OK
//	or 	-1 if error
//

int set_unpriv_UID_GID_doublecheck()
{	
	int err;

	if( getuid() == 0 ) return -1;
	if( getgid() == 0 ) return -1;
	if( geteuid() == 0 ) return -1;
	if( getegid() == 0 ) return -1;

	//
	// test for correct behavior: all next four syscalls must _not_ be successful
	//

	err = setuid( 0 );

	if( !err )
	{
		perror("ERROR: re-setuid(0)");
		return -1;
	}

	err = setgid( 0 );

	if( !err )
	{
		perror("ERROR: re-setgid(0)");
		return -1;
	}

	err = seteuid( 0 );

	if( !err )
	{
		perror("ERROR: re-seteuid(0)");
		return -1;
	}

	err = setegid( 0 );

	if( !err )
	{
		perror("ERROR: re-setegid(0)");
		return -1;
	}
	

	// finally we really need to be 
	//   GID == <secctl>
	// as we want to open /dev/secctl with group <secctl> permission
	
	
	if( getegid() != SECCTL_GID )
	{
		fprintf(stderr,"secctl: Wrong eGID (==%u). We expect eGID==%u !\n", getegid(), SECCTL_GID );
		return -1;
	}
	
	return 0;
}



// called by check_and_set_strict_ressource_limits()
//
// rc:
//
//	either 	 0 if OK
//	or 	-1 if error
//

int xsetrlimits(void)
{
	struct rlimit rl;
	int err;
  

	rl.rlim_cur = 4;  /* max. nb. of open files: stdin,stdout,stderr,/dev/secctl */
	rl.rlim_max = 4;

	err = setrlimit( RLIMIT_NOFILE, &rl);
       
        if(err) { perror("setrlimit"); return -1; }

	rl.rlim_cur = 0;  /* The maximum size of files that the process may create */
	rl.rlim_max = 0;

	err = setrlimit( RLIMIT_FSIZE, &rl);
       
        if(err) { perror("setrlimit"); return -1; }


	rl.rlim_cur = 0;  /* The  maximum  number  of  processes that can be created */
	rl.rlim_max = 0;

	err = setrlimit( RLIMIT_NPROC, &rl);
       
        if(err) { perror("setrlimit"); return -1; }


	rl.rlim_cur = 0;  /* Maximum size of core file.  */
	rl.rlim_max = 0;

	err = setrlimit( RLIMIT_CORE, &rl);
       
        if(err) { perror("setrlimit"); return -1; }
	
	return 0;
}




// called by main()
//
// rc:
//
//	either 	 0 if OK
//	or 	-1 if error
//

int check_and_set_strict_ressource_limits(char **env)
{
	int err;

	/***************************************************************
	 * in this program there should not be any dependence
	 * on any environment variable; however, it seems good practise
	 * for an admin tool to reset the environment
	 */
	   
	*env = NULL;
	
	// DEBUG( system("/bin/bash -c set"); )



	/**********************************************************
	 *
	 *  check if these *FILE are opened..
	 *  Note: we do not check whether these are indeed the
	 *  usual file descriptors. Our parent process could have
	 *  changed (dup*()) these descriptors to arbitrary descriptors.
	 */

	if( fileno(stdin)  != 0 ) return -1;
	if( fileno(stdout) != 1 ) return -1;
	if( fileno(stderr) != 2 ) return -1;


	/**********************************************************
	 *
	 * limit some process specific ressources
	 */

	err = xsetrlimits();
	
	if(err) return -1;
	
	
	/**********************************************************
	 *
	 * we don't want to be ptraced via > strace -p PID
	 * (even if we are not running suid/sgid)
	 *
	 * Note: this measure does not prevent tracing this program
	 * from the very start, like > strace secctl
	 * (since PR_SET_DUMPABLE is just not yet set at start)
	 *
	 */

	errno = 0;

	err = prctl( PR_SET_DUMPABLE, 0, 0, 0, 0 );
	
	if(err) { perror("prctl():"); return -1; }


	
	/**************** care for right UID & GID ****************/	

	DEBUG( fprintf(stderr,"DEBUG: uid=%u\teuid=%u\n", (u32) getuid(), (u32) geteuid() ); )
	DEBUG( fprintf(stderr,"DEBUG: gid=%u\tegid=%u\n", (u32) getgid(), (u32) getegid() ); )

	err = set_unpriv_UID_GID();

	if( err ) return -1;

	DEBUG( fprintf(stderr,"DEBUG: uid=%u\teuid=%u\n", (u32) getuid(), (u32) geteuid() ); )
	DEBUG( fprintf(stderr,"DEBUG: gid=%u\tegid=%u\n", (u32) getgid(), (u32) getegid() ); )

	err = set_unpriv_UID_GID_doublecheck();

	if( err ) return -1;

	/* we are now
	 *
	 *	anycase: uid > 0, euid > 0
	 *	maybe uid == euid == SECCTL_UID
	 *
	 *	anycase: egid == SECCTL_GID
	 *******************************************/

	err = sanity_validate_size_of_RTE();

	if(err) return -1;
	
	
	return 0;
}



// called by main();
//
// rc:
//
//	either 	 0 if OK
//	or 	-1 if error
//

int dispatch_cmd( u8 cmd, int fd )
{
	int err;
	err = 0;	
	
	
	switch( cmd )
	{
		case CMD_LSM_SET_RULE:		// show_RTE();

		case CMD_LSM_ON:
		case CMD_LSM_OFF:

		case CMD_LSM_DEFAULT_POLICY_ACCEPT:
		case CMD_LSM_DEFAULT_POLICY_DENY:

		case CMD_LSM_PRINTK_RULES:

		case CMD_LSM_CLEAR_RULES:

		case CMD_LSM_LOCK:		// <passwd> has been copied to RTE.<values>
		case CMD_LSM_LOCKM:		// <passwd> has been copied to RTE.<values>
		case CMD_LSM_UNLOCK:		// <passwd> has been copied to RTE.<values>

		DEBUG( case CMD_LSM_DEBUG_SIZE_TEST: )

						err = send_packet( fd );
						
						if(err) 
						{
							fprintf(stderr,"ERROR: send_packet() failed: CMD = 0x%X\n", cmd );
						}
						
						break;


		case CMD_LSM_SHOW_RULES:
		
						err = send_packet_and_receive( fd );
						
						if(err) 
						{
							fprintf(stderr,"ERROR: send_packet_and_receive() failed: CMD = 0x%X\n", cmd );
						}
						
						break;

		
		default: 			fprintf(stderr,"dispatch_cmd(): ERROR: unknown CMD : 0x%X\n", cmd ); 

						err = -1;
		
	}	
	
	return err;
}



/////////////////////////////////////////////////////////////////////////////////////////


int main(int argc, char **argv, char **env )
{
	int err;
	u8  cmd;
	int fd;
	char *pchar;

	BUILD_BUG_ON( sizeof(RULE_TABLE_ENTRY) != (RULE_TABLE_ENTRY_EXPECTED_SIZE ) );


#ifdef  ENABLE_STRICT_RESSOURCE_LIMITS

	err = check_and_set_strict_ressource_limits(env);
	
	if(err) exit(-1);
#endif


	/**************** early help *****************/
	
	if( argc == 1 ) usage_exit();
	
	if( argc == 2 )
	{
		pchar = argv[1];
		
		if( (*pchar == '-') || (*pchar == 'h') ) usage_exit();
	}



	/************** parse command line args -> global var RTE ***************/	
	
		
	// start cleanly with zero RTE
	// 
	
	memset( &RTE, 0, sizeof( RULE_TABLE_ENTRY ) );	
	
	cmd = parse_args( argc, argv );
	
	if( !cmd ) exit(-1);

	
	RTE.cmd = cmd;
	

	//	show_RTE();		//	DEBUG only


	/*************** safe open( SECCTL_DEVICE ) ****************/
	
	fd = safe_open_device();		
	
	if( fd < 0 ) exit(-1);
	


	/***************************************************************
	 * now write() global var RTE via /dev/secctl to KernelSpace LSM
	 * and possibly read() RTE packets back if one of CMD_LSM_SHOW_*
	 * options were given
	 ************************************************************/
	 
	(void) dispatch_cmd( cmd, fd );
	

	close(fd);	
	
	exit(0);
}

	
////////////////////////////////////////////////////////////////////////////////////////

/*
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
*/

/*
#define U16_MAX		((1<<16)-1)
#define U32_MAX		((1<<32)-1)
#define U64_MAX		((1<<64)-1)
*/

/*
#define U16_MAX		((u16)65535)
#define U32_MAX		((u32)4294967295)
#define U64_MAX		((u64)18446744073709551615)
*/

/*
#define U16_MAX		((u16)~0U)
#define U32_MAX		((u32)~0U)
#define U64_MAX		((u64)~0ULL)
*/



/*
void size_test(void)
{
	printf("secctl: sizeof(u8 ) = %d\n", (u32)sizeof(u8 ));
	printf("secctl: sizeof(u16) = %d\n", (u32)sizeof(u16));
	printf("secctl: sizeof(u32) = %d\n", (u32)sizeof(u32));
	printf("secctl: sizeof(u64) = %d\n\n", (u32)sizeof(u64));
	
	printf("secctl: U16_MAX = %llu\n",   (u64) U16_MAX );
	printf("secctl: U32_MAX = %llu\n",   (u64) U32_MAX );
	printf("secctl: U64_MAX = %llu\n\n", U64_MAX );
	
	printf("secctl: sizeof(char) = %d\n", (u32)sizeof(char));
	printf("secctl: sizeof(short) = %d\n", (u32)sizeof(short));
	printf("secctl: sizeof(int) = %d\n", (u32)sizeof(int));
	printf("secctl: sizeof(long) = %d\n", (u32)sizeof(long));
	printf("secctl: sizeof(unsigned char) = %d\n", (u32)sizeof(unsigned char));
	printf("secctl: sizeof(unsigned short) = %d\n", (u32)sizeof(unsigned short));
	printf("secctl: sizeof(unsigned int) = %d\n", (u32)sizeof(unsigned int));
	printf("secctl: sizeof(unsigned long) = %d\n", (u32)sizeof(unsigned long));
	printf("secctl: sizeof(unsigned long long) = %d\n", (u32)sizeof(unsigned long long));



	exit(0);
		
}
*/


/*
####################################################
results:

Knoppix 7.4 UserSpace
Linux Microknoppix 3.16.2-64 #6 SMP PREEMPT ... 2014 x86_64 

./main

secctl: sizeof(u8 ) = 1
secctl: sizeof(u16) = 2
secctl: sizeof(u32) = 4
secctl: sizeof(u64) = 8
secctl: sizeof(char) = 1
secctl: sizeof(short) = 2
secctl: sizeof(int) = 4
secctl: sizeof(long) = 4
secctl: sizeof(unsigned char) = 1
secctl: sizeof(unsigned short) = 2
secctl: sizeof(unsigned int) = 4
secctl: sizeof(unsigned long) = 4
secctl: sizeof(unsigned long long) = 8
*/




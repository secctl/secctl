/* common include file for secctl
 * ------------------------------
 * used for both KernelSpace LSM and
 * UserSpace admin tool as well;
 *
 *
 * ifdef SECCTL_KERNELSPACE: parts that are for KernelSpace LSM only;
 * ifdef SECCTL_USERSPACE: parts for UserSpace admin tool;
 * (if no ifdef, then common part)
 *
 * Copyright (C) 2015 (TomVt / secctl@t-online.de)
 * Copyright (C) 2012 (TomVt / secctl@t-online.de)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 */




#define	SECCTL_DEVICE			"/dev/secctl"
  
#define	SECCTL_DEVICE_MAJOR		40
#define	SECCTL_DEVICE_MINOR		0



 
#ifdef SECCTL_USERSPACE

#define U8_MAX		((u8)~0U)
#define U16_MAX		((u16)~0U)
#define U32_MAX		((u32)~0U)
#define U64_MAX		((u64)~0ULL)


typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

/* from $kernel/include/linux/bug.h 
 *  used for compile time check of sizeof(struct)
 */
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#endif


////////////////// RULE TABLE ENTRY (RTE) for RULE TABLE RT[] /////////////////////
//
// This struct is prototype for one entry in our RT[]
//
// size & alignment consideration:
//	sizeof( RTE ) == RULE_TABLE_ENTRY_EXPECTED_SIZE  (==80)
// which enables a nice 16 byte alignment;
// We do check this requirement at runtime with function 
//	sanity_validate_size_of_RTE()
// both in Kernel LSM as well as in UserSpace tool. If this check should fail,
// we exit. This better needs an explanation then.
//
// All .values are arranged to enable 4 byte alignment for all u32 and u64;
//
// see dcache.h: definition of DNAME_INLINE_LEN can vary: 32,36 or 40 bytes;
// We want to have a fixed size of our RTE, so we define our
// SECCTL_DNAME_INLINE_LEN to one of these values: the longest: 40 bytes.
// ... and take care when it comes to copying from pdentry->d_iname
//
// Maximum 40 bytes of d_iname[] is certainly a waste of space for most dnames;
// However, reserving less space for .d_iname[] would exclude the longer dnames.
// Calling kmalloc for any single d_iname would do, but doesn't seem worth the 
// effort, as the number of rules in a typical scenario is certainly limited.
// 
//
// Prototype RULE_TABLE_ENTRY has two(!) functions:
//  1) one entry in rule table RT[],
//  2) communication packet prototype for data and cmd transfer between Kernel-
//     and UserSpace (that's why we have items .cmd, .rule_nb, .checksum -- these
//     would not be necessary when we would use type RTE only for function 1))
//

#define SECCTL_DNAME_INLINE_LEN		40

#define RULE_TABLE_ENTRY_EXPECTED_SIZE	80

typedef struct
{
	u32	uid;		// of the running process (uid_t)		u32	4
	
	u8	mask;		// access mask					u8	1
	u8	mask_required;	// mask bits as required according to x,r,w,a	u8	1
	u8	mask_excluded;	// mask bits excluded according to x,r,w,a	u8	1
	u8	cmd;		// for reading from userspace			u8	1
	
	u16	rule_nb;	// for reading from userspace			u16	2
	u16	bitfield;	// see "bitfield values" below			u16	2
	
	u32	devID;		//						u32	4
	u64	i_ino;		// of the inode					u64	8
	u32	i_uid;		// of the inode	(uid_t)				u32	4
	u16	i_mode;		// of the inode	(umode_t)			u16	2
	u8	which_hook;	// for logging which hook called us		u8	1
	u8	d_iname_len;	// unused; could speed up strncmp in future	u8	1	
	char	d_iname[ SECCTL_DNAME_INLINE_LEN ];	//				40
	
	u32	account;	// account++ if rule is matched			u32	4
	u32	checksum;	// for communication UserSpace<->KernelSpace	u32	4
}
 RULE_TABLE_ENTRY;

// Note: .d_iname_len is for alignment only (u16 + u8 + u8 == u32)
// and is currently set to 0 in function sanity_check_RTE() to convince
// the compiler to not optimize it away; To see the actual size of some RTE entries
// at runtime, do call CMD_LSM_DEBUG_SIZE_TEST via secctl UserSpace admin tool,
// which does invoke our debug function secctl_print_sizeof()
// (need to #define DEBUG_SIZE_TEST_ACTIVE below)


///////////////////////////////////////////////////////////////////////////////
// maximum number of rules in rule table RT[] (in units of RULE_TABLE_ENTRY)
//
// RT_MAX-1 needs to fit into RT[].rule_nb which is of type u16 currently
//  (max. nb. of 65536 rules should be really sufficient for a typical ruleset)
//
// We do pre-allocate space for our entire RT[] once while the LSM is initialized.
// With RT_MAX==256 and sizeof(RULE_TABLE_ENTRY)==80
// we would kalloc 256 x 80 = 20480 bytes.

#define RT_MAX	256

#if RT_MAX > 65535 
# error "RT_MAX too big!"
#endif



///////////////////// MOUNT TABLE /////////////////////////////////////////////

#ifdef SECCTL_KERNELSPACE

#define MAX_DEV_NAME_LEN	32
#define MAX_TYPE_LEN 		32

typedef struct
{
	// initialized to <UNUSED> by secctl_init()
	unsigned int 		status;
	
	// holds "global_mountID" for a filesystem,
	// assigned in secctl_intercept_sb_kern_mount()
	u32	 		s_mntID;

	u32	 		devID;
	
	// not unique ID, see include/uapi/linux/magic.h
	unsigned long 		s_magic;
	
	// pointer to superblock of a filesystem
	// assigned in secctl_intercept_sb_kern_mount()
	struct super_block	*psb;
	
	// following values are retrieved from superblock 
	// of a filesystem; for informational purpose only
	// see secctl_intercept_sb_mount()
	
	unsigned long		flags;
	char			d_iname[ SECCTL_DNAME_INLINE_LEN ];
	char			dev_name[ MAX_DEV_NAME_LEN ];
	char			type[ MAX_TYPE_LEN ];
	u8 s_id[32+4];		// "Informational name", see include/linux/fs.h
				// there is no symbolic constant that could be used instead of 32;
				// +4 is 1 for zero term and 3 for padding

}
MOUNT_TABLE_ENTRY;

#endif


////////////////////////////////////////////////////////////////
// bitfield values for RT[].bitfield
//  (USED and UNUSED are for MT[].status as well)
// if you change this, don't forget to change sanity_check_RTE()

#define UNUSED		0x0000

#define USED		0x0001
#define POLICY_ACCEPT	0x0002
#define POLICY_DENY	0x0004
#define LOGGING		0x0008

#define ANY_UID		0x0010
#define ANY_MASK	0x0020
#define ANY_I_INO	0x0040
#define ANY_I_UID	0x0080
#define ANY_I_MODE	0x0100
#define ANY_D_INAME	0x0200

#define ANY_ALL		( ANY_UID | ANY_MASK | ANY_I_INO | ANY_I_UID | ANY_I_MODE | ANY_D_INAME )

#define ANY_ACCEPT_LOG	( POLICY_ACCEPT | LOGGING | ANY_ALL )


#ifdef SECCTL_KERNELSPACE
// macros for checking RT[].bitfield

#define RT_USED( n ) 			( RT[n].bitfield & USED )
#define RT_POLICY_ACCEPT( n ) 		( RT[n].bitfield & POLICY_ACCEPT )
#define RT_POLICY_DENY( n ) 		( RT[n].bitfield & POLICY_DENY )
#define RT_LOGGING( n ) 		( RT[n].bitfield & LOGGING )

#define RT_ANY_UID( n ) 		( RT[n].bitfield & ANY_UID )
#define RT_ANY_MASK( n )		( RT[n].bitfield & ANY_MASK )
#define RT_ANY_I_INO( n ) 		( RT[n].bitfield & ANY_I_INO )
#define RT_ANY_I_UID( n ) 		( RT[n].bitfield & ANY_I_UID )
#define RT_ANY_I_MODE( n ) 		( RT[n].bitfield & ANY_I_MODE )
#define RT_ANY_D_INAME( n ) 		( RT[n].bitfield & ANY_D_INAME )

#define RT_ANY_ALL( n ) 		( ( RT[n].bitfield & ANY_ALL )==ANY_ALL )
#endif


#ifdef SECCTL_USERSPACE
// macros for checking RTE.bitfield
//  (these macros differ slightly from those for kernel-space-LSM above)

#define RTE_USED 		( RTE.bitfield & USED )
#define RTE_POLICY_ACCEPT	( RTE.bitfield & POLICY_ACCEPT )
#define RTE_POLICY_DENY 	( RTE.bitfield & POLICY_DENY )
#define RTE_LOGGING 		( RTE.bitfield & LOGGING )

#define RTE_ANY_UID 		( RTE.bitfield & ANY_UID )
#define RTE_ANY_MASK		( RTE.bitfield & ANY_MASK )
#define RTE_ANY_I_INO 		( RTE.bitfield & ANY_I_INO )
#define RTE_ANY_I_UID 		( RTE.bitfield & ANY_I_UID )
#define RTE_ANY_I_MODE 		( RTE.bitfield & ANY_I_MODE )
#define RTE_ANY_D_INAME 	( RTE.bitfield & ANY_D_INAME )

#define RTE_ANY_ALL	 	( (RTE.bitfield & ANY_ALL)==ANY_ALL )
#endif


#define RULE_NOT_FOUND	-1
#define RULE_FOUND	 0


///////////////////////////////////////////////////////////
// for RT[].cmd: command codes when reading from UserSpace
// via callback_write()

#define CMD_LSM_SET_RULE		0x01

#define CMD_LSM_ON    			0x10
#define CMD_LSM_OFF   			0x11

#define CMD_LSM_DEFAULT_POLICY_ACCEPT	0x12
#define CMD_LSM_DEFAULT_POLICY_DENY	0x13

#define CMD_LSM_PRINTK_RULES   		0x15

#define CMD_LSM_SHOW_RULES		0x16

#define CMD_LSM_CLEAR_RULES  		0x19
#define CMD_LSM_HELP			0x1A

#define CMD_LSM_LOCK			0x1F
#define CMD_LSM_LOCKM			0x20

#define CMD_LSM_UNLOCK			0x21



// to activate debug function secctl_print_sizeof()
// uncomment this 
#define DEBUG_SIZE_TEST_ACTIVE

#define CMD_LSM_DEBUG_SIZE_TEST		0xFF



#ifdef SECCTL_USERSPACE

#define MSG_LSM_ON			"on"
#define MSG_LSM_OFF			"off"

#define MSG_LSM_DEFAULT_POLICY_ACCEPT	"dpa"
#define MSG_LSM_DEFAULT_POLICY_DENY	"dpd"

#define MSG_LSM_PRINTK_RULES		"ksr"

#define MSG_LSM_SHOW_RULES		"sr"

#define MSG_LSM_CLEAR_RULES		"cr"

#define MSG_LSM_LOCK			"lock"
#define MSG_LSM_LOCKM			"lockm"
#define MSG_LSM_UNLOCK			"unlock"

#define MSG_LSM_DEBUG_SIZE_TEST		"dst"

#endif


#ifdef SECCTL_KERNELSPACE

// <which_hook> information is passed from calling hook to logging in RTE.which_hook

#define HOOK_BPRM_CHECK  		0x01
#define HOOK_INODE_PERMISSION		0x02
#define HOOK_INODE_UNLINK		0x03
#define HOOK_INODE_RENAME		0x04
#define HOOK_INODE_SETATTR		0x05
#define HOOK_INODE_RMDIR		0x06
#define HOOK_INODE_LINK			0x07

static char *hook_str_bprm = "bprm";
static char *hook_str_perm = "perm";
static char *hook_str_unlk = "unlk";
static char *hook_str_renm = "renm";
static char *hook_str_seta = "seta";
static char *hook_str_rmdr = "rmdr";
static char *hook_str_link = "link";

#endif

// #define DEBUG(x)	x
#define DEBUG(x)	(void)0;



// simple integrity function for elements of RTE
//
// Used both from UserSpace and KernelSpace
//
// .checksum field will be modified !
//
// rc: checksum (the calling function is responsible to use it somehow)
//

static u32 secctl_calc_RTE_checksum( RULE_TABLE_ENTRY *pRTE )
{

	u32 n32bitwords;
	u32 checksum;
	u32 *p32;
	u32 rounds;
	
	pRTE->checksum = 0;
	
	// calc simple checksum by adding 32bit elements neglecting carry

	n32bitwords = ((u32)sizeof( RULE_TABLE_ENTRY )) >> 2;
	
	checksum = 0;
	p32 = (u32*) pRTE;
	
	for( rounds = 0; rounds < n32bitwords; rounds++ )
	{
		checksum += *(p32++);
	}
	
	pRTE->checksum = checksum;
		
	return checksum;
}



// for UserSpace: since isalnum and isdigit from libc do respect "current locale"
// setting, we just don't know how it will give different results in different locale settings;
// And as we have a very clear requirement, we better write our own version. 
// We do _not_ respect any locale. 
// isalnum2() is also used in KernelSpace LSM
//
// contrary to our usual convention, these functions
// return
//		1 on SUCCESS,
//		0 on FAILURE


static inline int isalnum2( char c )
{
	if( c >= '0' && c <= '9' ) return 1;
	if( c >= 'a' && c <= 'z' ) return 1;
	if( c >= 'A' && c <= 'Z' ) return 1;
	
	return 0;
}


static inline int isletter2( char c )
{
	if( c >= 'a' && c <= 'z' ) return 1;
	if( c >= 'A' && c <= 'Z' ) return 1;
	
	return 0;
}

static inline int isdigit2( char c )
{
	if( c >= '0' && c <= '9' ) return 1;
	
	return 0;
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// These are special chars for object names which we do store
// in RTE.d_iname[]. Alphanumeric characters [a-zA-Z0-9] are accepted 
// already implicitely, see sanity_check_diname().
// 
// see explanation in UserSpace tool ("STEP 3")

#define SECCTL_FILENAME_ADMISSIBLE_SPECIAL_CHARS  "_-.=+"

//
// check whether 'c' is admissible
//

static inline int isspecial2( char c )
{
	char *p;
	
	p = SECCTL_FILENAME_ADMISSIBLE_SPECIAL_CHARS;
	
	while( *p )
	{
		if( *p++ == c ) return 1;
	}
	
	return 0;
}



// check diname[] for valid chars
//
// Used both from UserSpace and KernelSpace
//
// arg #diname_buf_len is length of buffer, not length of diname
//
// we force zero term !
//
// if <subst> param is given (not 0x0) then we substitute any invalid char by <subst> char, e.g. '.'
//
// rc:
// 	0: case 1a:  special case: one single '/' for root inode : OK (the only acceptable case with a / in diname)
// 	0: case 1b:  common case: diname has all valid chars, and zero term.
// 	-1: case 2:  error: #diname_buf_len out of bounds OR invalid char found (and no <subst> param given)

static int sanity_check_diname( char *diname, int diname_buf_len, char subst )
{
	int i;
	char c;

	if( ( diname_buf_len < 2 ) ||			
	    ( diname_buf_len > SECCTL_DNAME_INLINE_LEN ) ) return -1;	// case 2
	    

	if( (diname[0] == '/') &&
	    (diname[1] == 0  )    )    return 0;			// case 1a

	diname[ diname_buf_len-1 ] = 0;

	for( i=0; i<diname_buf_len; i++ )
	{
		c = diname[i];

		// we better be strict here on possible chars within filenames;
		//  if need be to have strange chars like % or ' ' or '(' in filenames,
		//  then ease these checks at your own risk
		
		if( isalnum2(c) ) continue;
		
		//
		// check for special char, which might be allowed by SECCTL_FILENAME_ADMISSIBLE_SPECIAL_CHARS
		// 

		if( isspecial2(c) ) continue;
		
		//
		// zero term ?
		//

		if( c == 0x0 ) break;				

		
		// unexpected char found:
		// fprintf(stderr,"ERROR: <filename> has invalid char <%c> at pos %d\n", (int)c, i );
		
		if( ! subst )	return -1;			// case 2
		
		diname[i] = subst;
	}
	
	return 0;						// case 1b
	
}


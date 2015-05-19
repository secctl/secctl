/*
 * secctl LSM (Linux Security Module)
 *
 * KernelSpace implementation of LSM hook functions
 *
 * Copyright (C) 2015 (TomVt / secctlfb * at * t-online dot de)
 *	rule decision engine rewritten (x,r,w,a)
 *	MountID substituted by DeviceID (major/minor of device)
 *	moved prelim. rule parser from Kernel to UserSpace;
 * 	implies a new protocol for communication between Kernel<->UserSpace;
 *      => a new UserSpace admin tool <secctl> was written;
 *
 * Copyright (C) 2012 (TomVt / secctlfb * at * t-online dot de)
 *	initial implementation for Kernel 3.2.4
 *	simple rule decision engine (hex value only)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * -------------------------------------------------------------------------
 *
 * see README file for an introduction
 *
 * -------------------------------------------------------------------------
 *
 * note: "default policy deny" is not tested
 *
 * -------------------------------------------------------------------------
 *
 * note that copied comments from $kernel/include/linux/security.h are from
 * an older kernel (3.2.4), so do not rely too much on it. Better look
 * into include/linux/security.h of current kernel.
 *
 * -------------------------------------------------------------------------
 *
 * before compilation: do enable/disable DEBUG() ... see common.h
 *
 */

#include <linux/kernel.h>
#include <linux/bug.h>
#include <linux/security.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/ctype.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/user_namespace.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dcache.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/binfmts.h>
#include <linux/spinlock.h>

#define SECCTL_KERNELSPACE
#include "common.h"


//////////////////////////////////////////////////////////////////
// RT[]: rule table which holds all rules used for decision engine
//
// we will kmalloc the entire space for RT[]; for distribution kernels a
// linked list would be better, but implies more complexity in the code.
//
// Alternatively we could introduce a kernel boot param #secctl_rt_size
// for easy adjustment of RT[] size (not implemented currently).
//
// concurrency/preemption consideration:
//
// After initial and controlled loading of rules into RT[],
// any subsequent access to RT[] from calling hook is read-only.
// So we get rid of concurrency/preemption issues quite easily,
// except
//    "RT[rule_nb].account++" in function secctl(),
// see explanation in secctl() below.
//
// Loading of rules is done
//
//  administratively by putting rules via /dev/secctl from UserSpace
//  (with RTE.cmd = CMD_LSM_SET_RULES) and
//  reading them
//  via	callback_write() ->
//		sanity_check_RTE() ->
//			sanity_check_diname()
//		memcpy( &RT[ RTE.rule_nb ], &RTE, size_RTE );

static RULE_TABLE_ENTRY  *RT;


// since we allow holes in our rule table RT[], for quick lookup of valid
// rules, we use a LOOKUP_INDEX[]
//
// example:
//
//  RT[0] has valid rule0
//  RT[1] has valid rule1
//  RT[2] has no valid rule
//  ...
//  RT[9] has no valid rule
//  RT[10] has valid rule10
//  RT[11] has valid rule11
//
// our LOOKUP_INDEX[] would then look like:
//
// LOOKUP_INDEX[0] = 0
// LOOKUP_INDEX[1] = 1
// LOOKUP_INDEX[2] = 10
// LOOKUP_INDEX[3] = 11
//
// #N_RULES would be == 4 in this example.
//
// You better avoid those holes, since a contiguous rule-set
// would allow better cache/timing behavior.
//
// see update_lookup_index() which is called each time the LSM is activated.
// see find_match_uid() and find_match_uid() for use of LOOKUP_INDEX[] then.
//


static u16		*LOOKUP_INDEX;


// number of current active rules in RT[]
//  will be set in update_lookup_index()

static u32		N_RULES;


//
// mainly for debug purposes to see what filesystems the kernel does mount;
// If you don't need this, you can safely comment out this global var,
// and (void/return 0) these two functions (we should have a pragma switch..)
//
//  secctl_intercept_sb_mount()
//  secctl_intercept_sb_kern_mount()
//

static MOUNT_TABLE_ENTRY  MT;


// 
//
//

static u8 callback_readmode = CMD_LSM_SHOW_RULES;


// 
// current global status definitions for our LSM
//

#define SECCTL_UNLOCKED		0
#define SECCTL_LOCKED		1
#define SECCTL_LOCKED_MOUNT	2

static int 	secctl_locked = SECCTL_UNLOCKED;

static u64	lock_wait_for_jiffie64;
static u32	lock_wait_for_jiffie32;

// minimum wait period for unlock retries (with password)

#define SECCTL_UNLOCK_WAIT_SECONDS	10



//////////////////////////////////////////////////////////////////////////////
// SECCTL_DEFAULT : Global policy for LSM --
//	will be returned if there is no matching rule found
//	or some error will be encountered;
//	can be set to SECCTL_ACCEPT or SECCTL_DENY
//
// NOTE: SECCTL_DEFAULT == SECCTL_DENY is not tested!
//
//      so far we set
//	SECCTL_DEFAULT := SECCTL_ACCEPT
//	and use a whitelist rule set,
//      plus a final deny rule for a given filesystem (MntID)
//	(that is explicit policy DENY for a given filesystem)

#define SECCTL_DENY	(-EPERM)
#define SECCTL_ACCEPT	(0)

static int SECCTL_DEFAULT = SECCTL_ACCEPT;

/////////////////////////////////////////
// global switch : LSM off / on
// 
// off(0): no rule checking is done; SECCTL_ACCEPT is returned immediately from any LSM hook.
//
//  on(1): rule checking is enforced:
//      
//
// will be set to 1 when
// command CMD_LSM_ON was received via /dev/secctl
//
// will be (re-)set to 0 when CMD_LSM_OFF is received via /dev/secctl

static int secctl_active = 0;


static char 	*empty = "<empty>";



// for secctl_log(): 
//  enable/disable printk() logging of current rule match
//   (if (RT[rule].bitfield & LOGGING) )

static int printk_logging = 1;	



///////////// function prototypes /////////////////////////////////

static int secctl_intercept_bprm_check(struct linux_binprm *bprm);

static int secctl_intercept_inode_permission(struct inode *inode, int mask);
static int secctl_intercept_inode_unlink(struct inode *dir, struct dentry *dentry);
static int secctl_intercept_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);
static int secctl_intercept_inode_setattr(struct dentry *dentry, struct iattr *attr);
static int secctl_intercept_inode_rmdir(struct inode *dir, struct dentry *dentry);
static int secctl_intercept_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);

static int secctl_intercept_sb_kern_mount( struct super_block *sb, int flags, void *data );
static int secctl_intercept_sb_mount( const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data );
static int secctl_intercept_sb_umount( struct vfsmount *mnt, int flags );
static int secctl_intercept_sb_remount( struct super_block *sb, void *data);

static int secctl( struct inode *inode, struct dentry *dentry, unsigned int mask, u8 which_hook );
static int find_match_uid( u32 curr_uid, u32 *candidate );
static int find_match( RULE_TABLE_ENTRY *CURRENT, u32 candidate, u32 *rule_nb );

static void secctl_printk_rules(void);
static void secctl_clear_rules(void);
void secctl_print_sizeof(void);
static void update_lookup_index(void);

static void secctl_log( RULE_TABLE_ENTRY *CURRENT );

static int sanity_validate_size_of_RTE(void);
static int sanity_check_RTE( RULE_TABLE_ENTRY *pRTE );
static void sanitize_diname( char *diname, int diname_buf_len );

static u32 local_get_euid( kuid_t kuid );


/* LSM hook intercept
 *
 * from include/linux/security.h:
 *
 * @bprm_check_security:
 *	This hook mediates the point when a search for a binary handler will
 *	begin.  It allows a check the @bprm->security value which is set in the
 *	preceding set_creds call.  The primary difference from set_creds is
 *	that the argv list and envp list are reliably available in @bprm.  This
 *	hook may be called multiple times during a single execve; and in each
 *	pass set_creds is called first.
 *	@bprm contains the linux_binprm structure.
 *	Return 0 if the hook is successful and permission is granted.
 *
 *      include/linux/binfmts.h
 *
 *      struct linux_binprm { ...
 *	   struct file * file;
 *	   const char * filename;  Name of binary as seen by procps
 *	   const char * interp;	   Name of the binary really executed. Most
 *				   of the time same as filename, but could be different..
 *
 */

static int secctl_intercept_bprm_check(struct linux_binprm *bprm)
{
	struct inode *pinode;

	
#define SECCTL_DEBUG_LOG_EXEC
#ifdef SECCTL_DEBUG_LOG_EXEC

	u32 uid;

	// special logging of any exec() syscall regardless of secctl_active or not
	// This is a DEBUG feature - not enabled by default - .filename and .interp are not sanitized

	uid = local_get_euid( current_euid() );

	if( bprm->filename && bprm->interp )
		printk("secctl: bprm uid=%u: %s (%s)\n", uid, bprm->filename, bprm->interp );
	else
	if( bprm->filename )
		printk("secctl: bprm uid=%u: %s\n", uid, bprm->filename );
	else
		printk("secctl: bprm uid=%u:  ?\n", uid );
#endif



	if( ! secctl_active ) return SECCTL_ACCEPT;


	pinode = file_inode( bprm->file );

	if( ! pinode ) return SECCTL_DEFAULT;			// what's this? an exec(file) without an inode ?

	
	
	return secctl( pinode, NULL, MAY_EXEC, HOOK_BPRM_CHECK );
}




/* LSM hook intercept
 *
 * from include/linux/security.h:
 *
 * @inode_rename:
 *	Check for permission to rename a file or directory.
 *	@old_dir contains the inode structure for parent of the old link.
 *	@old_dentry contains the dentry structure of the old link.
 *	@new_dir contains the inode structure for parent of the new link.
 *	@new_dentry contains the dentry structure of the new link.
 *	Return 0 if permission is granted.
 */
 
static int secctl_intercept_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
				 struct inode *new_dir, struct dentry *new_dentry)
{
	int rc;

	if( ! secctl_active ) return SECCTL_ACCEPT;

	
	rc = secctl( NULL, old_dentry, MAY_WRITE, HOOK_INODE_RENAME );
	
	//
	// rc can be SECCTL_DENY || SECCTL_ACCEPT
	// iff OK for old_dentry, we have to check for new_dentry
	//
	
	if( rc == SECCTL_ACCEPT )
	{
		rc = secctl( NULL, new_dentry, MAY_WRITE, HOOK_INODE_RENAME );
	}
	
	
	return rc;		

}


/* LSM hook intercept
 *
 * from include/linux/security.h:
 *
 * @inode_unlink:
 *	Check the permission to remove a hard link to a file.
 *	@dir contains the inode structure of parent directory of the file.
 *	@dentry contains the dentry structure for file to be unlinked.
 *	Return 0 if permission is granted.
 */

static int secctl_intercept_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if( ! secctl_active ) return SECCTL_ACCEPT;

	return secctl( NULL, dentry, MAY_WRITE, HOOK_INODE_UNLINK );
}



/* from include/linux/security.h:
 *
 * @inode_permission:
 *	Check permission before accessing an inode.  This hook is called by the
 *	existing Linux permission function, so a security module can use it to
 *	provide additional checking for existing Linux permission checks.
 *	Notice that this hook is called when a file is opened (as well as many
 *	other operations), whereas the file_security_ops permission hook is
 *	called when the actual read/write operations are performed.
 *	@inode contains the inode structure to check.
 *	@mask contains the permission mask.
 *	Return 0 if permission is granted.
 *
 *   this lsm hook is called by fs/namei.c -> inode_permission()
 */

static int secctl_intercept_inode_permission(struct inode *inode, int mask)
{
	if( ! secctl_active ) return SECCTL_ACCEPT;

	return secctl( inode, NULL, (unsigned int)mask, HOOK_INODE_PERMISSION );
}



/* LSM hook intercept
 * 
 * from include/linux/security.h:
 *
 * @inode_setattr:
 *	Check permission before setting file attributes.  Note that the kernel
 *	call to notify_change is performed from several locations, whenever
 *	file attributes change (such as when a file is truncated, chown/chmod
 *	operations, transferring disk quotas, etc).
 *	@dentry contains the dentry structure for the file.
 *	@attr is the iattr structure containing the new file attributes.
 *	Return 0 if permission is granted.
 */
 
static int secctl_intercept_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	if( ! secctl_active ) return SECCTL_ACCEPT;

	return secctl( NULL, dentry, MAY_WRITE, HOOK_INODE_SETATTR );
}


/* LSM hook intercept
 *
 * from include/linux/security.h:
 *
 * @inode_rmdir:
 *	Check the permission to remove a directory.
 *	@dir contains the inode structure of parent of the directory to be removed.
 *	@dentry contains the dentry structure of directory to be removed.
 *	Return 0 if permission is granted.
 */

static int secctl_intercept_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	if( ! secctl_active ) return SECCTL_ACCEPT;

	return secctl( NULL, dentry, MAY_WRITE, HOOK_INODE_RMDIR );
}


/* LSM hook intercept
 *
 * from include/linux/security.h:
 *
 * @inode_link:
 *	Check permission before creating a new hard link to a file.
 *	@old_dentry contains the dentry structure for an existing link to the file.
 *	@dir contains the inode structure of the parent directory of the new link.
 *	@new_dentry contains the dentry structure for the new link.
 *	Return 0 if permission is granted.
 */
 
static int secctl_intercept_inode_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	int rc;

	if( ! secctl_active ) return SECCTL_ACCEPT;
	
	rc = secctl( NULL, old_dentry, MAY_WRITE, HOOK_INODE_LINK );
	
	//
	// rc can be SECCTL_DENY || SECCTL_ACCEPT
	// iff OK for old_dentry, we have to check for new_dentry
	//
	
	if( rc == SECCTL_ACCEPT )
	{
		rc = secctl( NULL, new_dentry, MAY_WRITE, HOOK_INODE_LINK );
	}
	
	return rc;		
}


///////////////////////////////////////////////////////////////////////////////////
// our main control function invoked by secctl_intercept* LSM hook functions above
//
// called iff secctl_active == 1 (checked in calling function already)
//
// strategy for this function:
//
// a)	from inode||dentry we retrieve further information
//   	about subject and object, and put it into local var RTE_CURRENT
//
// b)	having UID, check early and quickly for possible rule match
//		find_match_UID()
//
// c)	retrieve further information about current access 
//
// d)   call find_match() to compare RTE_CURRENT to valid rules in RT[]
//      If there is a matching rule, respective policy from that particular 
//      rule is returned (either SECCTL_ACCEPT or SECCTL_DENY).
//
// rc: 
//  either	SECCTL_ACCEPT	if accept-rule has been found
//  or		SECCTL_DENY	if deny-rule has been found
//  or implicit SECCTL_DEFAULT	if error or no matching rule found
///////////////////////////////////////////////////////////////////////////////

static int secctl( struct inode *inode, struct dentry *dentry, unsigned int mask, u8 which_hook )
{

	struct dentry		*pdentry;
	struct inode 		*pinode;
	int			inode_valid, d_iname_valid, devID_valid;
		
	RULE_TABLE_ENTRY	RTE_CURRENT;
	
	u32			candidate;
	u32			rule_nb;
	u32			uid;
	kuid_t                  kuid_tmp;
	
	u32			deny_exec_linker;
	
	int			rc;


	if( inode )
	{
		/* include/linux/fs.h :
		 *
		 * 	#define S_DEAD		.. "removed, but still open directory"
		 * 	#define S_PRIVATE	.. "Inode is fs-internal"
		 */

		if( IS_PRIVATE(inode) )	return SECCTL_DEFAULT;		// will be checked again (see below)
		if( IS_DEADDIR(inode) )	return SECCTL_DEFAULT;
	}



	if( inode == NULL && dentry == NULL ) return SECCTL_DEFAULT;
	

	pinode = NULL;		// we use pointer copies
	pdentry = NULL;
	
	
	if( inode ) pinode = inode;
	if( dentry ) pdentry = dentry;
	
	


	///////////////////////////////////////////////////////////////////////////
	// 1st quick rule check: do we have a rule for this (uid) at all ?
	//

	uid = local_get_euid( current_euid() );
	
	rc = find_match_uid( uid, &candidate );
	
	if( rc == RULE_NOT_FOUND )
	{
		return SECCTL_DEFAULT;
	}

	// to avoid checking all those rules _before_ RT[ LOOKUP_INDEX[#candidate] ] again,
	// we pass #candidate to 2nd rule check: find_match()
	// that is starting further checks with RT[ LOOKUP_INDEX[#candidate] ]
	///////////////////////////////////////////////////////////////////////////



	///////////////////////////////////////////////
	//
	// if dentry was not given as param,
	//  then 1st get pdentry from inode 
	//

	if( pdentry == NULL )
	{

		pdentry = d_find_alias( inode );			// get dentry from inode ...
									//  see fs/dcache.c ... will use spinlock

		if( ! pdentry )
		{
			return SECCTL_DEFAULT;
		}
	}
	
	//
	// in any case:
	//  now we have pdentry
	//
	///////////////////////////////////////////////


	memset( &RTE_CURRENT, 0, sizeof( RULE_TABLE_ENTRY ) );	


	RTE_CURRENT.uid = uid;						// have retrieved uid some lines above already



	/*****************************************************
	 *
	 * now retrieve d_iname from pdentry
	 * and (if necessary, pinode from pdentry)
	 *
	 * howto lock this dentry to retrieve pdentry->d_iname :
	 * see $kernel/include/dcache.h :
	 *
	 *
	 *	dget, dget_dlock -	get a reference to a dentry
	 *	@dentry: dentry to get a reference to
	 *
	 *	Given a dentry or %NULL pointer increment the reference count
	 *	if appropriate and return the dentry. A dentry will not be 
	 *	destroyed when it has references.
	 *
	 *  dget() uses spin_lock( &pdentry->d_lock ) to increment the
	 *  reference counter dentry->d_count++;
	 *
	 *  have to make sure that we have a dput() in any case !
	 *
	 *  possibly we could us a direct 
	 *	 *	spin_lock( &pdentry->d_lock )
	 * ... spin_unlock(..) alternatively
	 */
	 
	 

	pdentry = dget( pdentry );

	if( ! pdentry )
	{
		//  cannot go on
		
		return SECCTL_DEFAULT;
	}
	

	d_iname_valid = 0;

	if( pdentry->d_iname )
	{
		/* for zero termination: see dcache.c: __d_alloc():
		 *  "We guarantee that the inline name is always
		 *   NUL-terminated."
		 *   dentry->d_iname[DNAME_INLINE_LEN-1] = 0;
		 * -----------------------------------------------
		 * however, we note that kmem_cache_alloc() is not called with __GFP_ZERO
		 *
		 *
		 * note: our constant SECCTL_DNAME_INLINE_LEN = max( poss. values of DNAME_INLINE_LEN)
		 *		that is: 40 = max(32,36,40)
		 */ 
		 
		if( DNAME_INLINE_LEN <= SECCTL_DNAME_INLINE_LEN )
		{
			strncpy( RTE_CURRENT.d_iname, pdentry->d_iname, DNAME_INLINE_LEN );
		}
		else
		{
			// DNAME_INLINE_LEN > SECCTL_DNAME_INLINE_LEN !?
			//
			// this case should not happen, as we have carefully
			// defined SECCTL_DNAME_INLINE_LEN (40) >= DNAME_INLINE_LEN (32,36,40)
			// see dcache.h
			
			strncpy( RTE_CURRENT.d_iname, pdentry->d_iname, SECCTL_DNAME_INLINE_LEN );
		}
			

		// We might better force zero term. There might be more places
		// in the kernel where this string gets overwritten
		
		RTE_CURRENT.d_iname[SECCTL_DNAME_INLINE_LEN-1] = 0;

		d_iname_valid = 1;
	}

	if( !d_iname_valid )
	{
		//
		// then there was a NULL pointer ( pdentry->d_iname )
		// or d_find_alias() did return NULL
		//
		// this really should not happen ...

		dput( pdentry );

		return SECCTL_DEFAULT;
	}


	if( pinode == NULL )			// inode was not given as param to secctl()
	{
		inode_valid = 0;

		if( pdentry->d_inode )
		{
			pinode = pdentry->d_inode;

			inode_valid = 1;
		}

		if( !inode_valid )
		{
			//
			// then there was a NULL pointer ( pdentry->d_inode )
			// this really should not happen ...

			dput( pdentry );

			return SECCTL_DEFAULT;
		}


	}

	dput( pdentry );




	// NOW:
	//  we HAVE valid pdentry (mind the _p_)
	//  we HAVE valid pinode  (mind the _p_)
	// AND
	//  we HAVE retrieved RTE_CURRENT.d_iname[] 
	//
	
	// sanity checks again:
	
	if( pdentry == NULL ) return SECCTL_DEFAULT;
	if( pinode == NULL ) return SECCTL_DEFAULT;	
			
			
	// could be that we have retrieved pinode from a dentry,
	//  that's why we call IS_*() again
	
	if( IS_PRIVATE(pinode) ) return SECCTL_DEFAULT;
	if( IS_DEADDIR(pinode) ) return SECCTL_DEFAULT;	


	if( pinode->i_sb == NULL ) return SECCTL_DEFAULT;
			


	//////////////////////////////////////////////////////////////////////////////
	// NOW we go on to retrieve further .attributes. from *pinode and *pdentry
	//////////////////////////////////////////////////////////////////////////////
	


	////////////////////////////////////////////////////////////////////////////
	//
	// HOWTO lock an inode-struct: see inode_get_bytes() in fs/stat.c
	// spin_lock(&inode->i_lock);
	//	...
	// spin_unlock(&inode->i_lock);
	//
	
	devID_valid = 0;

	spin_lock(&pinode->i_lock);

		RTE_CURRENT.i_ino  = (u64) pinode->i_ino;

		kuid_tmp = pinode->i_uid;
		
		RTE_CURRENT.i_mode = (u16) pinode->i_mode;
		
		if( pinode->i_sb )
		{
			/* get deviceID to identify the filesystem this inode is accessed from */
		
			RTE_CURRENT.devID = pinode->i_sb->s_dev;
			
			devID_valid = 1;
		
		}

	spin_unlock(&pinode->i_lock);


	// call local_get_euid() outside spinlock
	
	RTE_CURRENT.i_uid = local_get_euid( kuid_tmp );

	

	if( ! devID_valid )
	{
		//
		// then there was a NULL pointer (->i_sb)
		//
		// as we do not have valid devID information, we cannot go on
		
		return SECCTL_DEFAULT;
	}


	////////////////////////////////////////////////////////////////////////////
	// access <mask> from calling hook funtion

	RTE_CURRENT.mask = (u8) (mask & 0xFF);

		
	
	//////////////////////////////////////////////////////////////////
	// now for the <inode> in question, we have
	//
	// RTE_CURRENT.uid
	// RTE_CURRENT.mask
	// RTE_CURRENT.devID
	// RTE_CURRENT.i_ino
	// RTE_CURRENT.i_uid
	// RTE_CURRENT.i_mode
	// RTE_CURRENT.d_iname
	//
	//////////////////////////////////////////////////////////////////


	//////////////////////////////////////////////////////////////////////////
	// 2nd rule check: complete check ...
	//  (we start with 
	//	RT[ LOOKUP_INDEX[#candidate] ]
	//   from 1st quick rule check above)
		
	rc = find_match( &RTE_CURRENT, candidate, &rule_nb );

	if( rc == RULE_NOT_FOUND )
	{
		// there simply was no matching rule for this access
		
		return SECCTL_DEFAULT;
	}

	//
	// matching rule found:
	//
	
	if( (rule_nb >= 0) && (rule_nb < RT_MAX) )
	{

		/* special check for runtime linker ld.so :
		 *	case 1: > exec(program) does invoke ld.so : OK
		 *	case 2: > ld.so program : NOT OK, since program would not be started by exec syscall.
		 *		This would be a bypass to our rule-set. Normally only needed for ldd command.
		 *
		 * Note: For .mask=='x' or .mask=='l' :
		 *	 we strongly recommend to use secctl with a whitelist rule-set only
		 *	 (a blacklist would not be able to control ld.so)
		 *
		 *	 For other .mask attributes (rwa) a whitelist or a blacklist can be used.
		 *
		 */

		if( (RT[rule_nb].mask == 'l') && (which_hook == HOOK_BPRM_CHECK) )
		{

			// This is case 2 : We were called from bprm exec syscall hook,
			//		and we do have a match in RT[] with ld.so

			deny_exec_linker = 1;				// <<<----- exception for ld.so
		}
		else
		{
			deny_exec_linker = 0;
		}
			
			
	
	
		RT[rule_nb].account++;		// don't care for overflow (u32) or preemption;
						//
						// This is indeed the single point where we do _write_
						// to our global RT[] while being called from any lsm hook; 
						// Any other access to RT[] is _read-only_ 
						//    see find_match_uid() and
						//        find_match()
						//
						// in rare case it can happen that two or more processes
						// do increment this counter at the very same time,
						// which could result in just +1 , although the correct result 
						// should be +2 then (for two processes) ... we accept this
						// behavior so far; a simple spinlock would prevent this,
						// but for the time being we opt for speedy code and
						// accept the rare case. 
						// So do not rely on this .account too much
						// (or introduce a spinlock if need be)
						//
						// Please note also, that if UserSpace does access an object,
						// the kernel might call one or multiple of our LSM hooks,
						// which does result in incrementing .account also multiple
						// times if a rule was matching.
						
						

		if( RT_LOGGING(rule_nb) )
		{
			// finalize temporary .items for logging,
			//  in particular we use .account for logging of relative time information
			//  (real accounting is done above, see global RT[].account++)
			//
			// Note: we only work on temporary local var RTE_CURRENT.* here;
			//	 we do _not_ change RT[rule_nb].* !
			//

			RTE_CURRENT.account    = (u32) jiffies;		// kernel var <jiffies> can be 64 or 32 bit 
			RTE_CURRENT.rule_nb    = rule_nb;
			RTE_CURRENT.which_hook = which_hook;
			RTE_CURRENT.bitfield   = RT[rule_nb].bitfield;
			
			if( deny_exec_linker )				// <<<----- exception for ld.so
			{
				RTE_CURRENT.bitfield |= POLICY_DENY;	// set DENY bit

				RTE_CURRENT.bitfield &= ~POLICY_ACCEPT;	// clear ACCEPT bit
			}
			
			secctl_log( &RTE_CURRENT );
		}
		
		// Final assignation of return code #rc
		//
		// Note: this assignation need to work independendly of RT_LOGGING yes/no !
		//
		

		if( RT_POLICY_ACCEPT(rule_nb) )	rc = SECCTL_ACCEPT;	// macros do operate on RT[rule_nb].bitfield
		if(   RT_POLICY_DENY(rule_nb) )	rc = SECCTL_DENY;
		
		if( deny_exec_linker ) 		rc = SECCTL_DENY;	// <<<----- exception for ld.so
				
		return rc;						// == SECCTL_ACCEPT || SECCTL_DENY
		
		
		// ----------------- this is the end of regular actions in secctl() --------------------------------
	}

	
	// ---- exception case: we should NOT BE HERE ----

	// for logging, we can only rely on RTE_CURRENT,
	// not on RT[rule_nb] (since #rule_nb seems to be invalid)
	// in particular, we do not have .policy

	RTE_CURRENT.account    = (u32) jiffies;
	RTE_CURRENT.rule_nb    = (u32) rule_nb;	// invalid, but do log it
	RTE_CURRENT.which_hook = which_hook;
	RTE_CURRENT.bitfield   = USED;		// do not set POLICY bit
						// policy will be printked as "oops"
	secctl_log( &RTE_CURRENT );

	
	return SECCTL_DENY;
}





//
// eval. quickly to see if we have a rule for this running UID at all
//   (called early in secctl())
//
// rc: 
//  either	#RULE_NOT_FOUND (-1)
//  or		#RULE_FOUND	0	(OK: possibly matching rule found)
//
// and		*candidate (2nd param)
//		lookup index (i) of possibly matching rule
//		-- will be propagated as candidate rule
//		to find_match()

static inline int find_match_uid( u32 curr_uid, u32 *candidate )
{
	u32 i;
	u32 rule_nb;
	
	// global var N_RULES has been initialized in update_lookup_index()
	
	for( i = 0; i < N_RULES; i++ )
	{
		rule_nb = (u32) LOOKUP_INDEX[i];
		
		if( RT_ANY_UID(rule_nb) )
		{
			*candidate = i;

			return RULE_FOUND;
		}
		
		if( RT[rule_nb].uid == curr_uid )
		{ 
			*candidate = i;

			return RULE_FOUND;
		}
	}
	
	return RULE_NOT_FOUND;
}




// for CURRENT find exact match (incl. wildcard match) in RT[]
// 
// rc: 
//  either	-1 : #RULE_NOT_FOUND
//  or: 	 0 : #RULE_FOUND
//
// and:		3rd param: *rule_nb_match : matching rule number (0...(RT_MAX-1))
//			(this is the real rule number; not the index number from LOOKUP_INDEX[])
//

static inline int find_match( RULE_TABLE_ENTRY *CURRENT, u32 candidate, u32 *rule_nb_match )
{
	u32 i;
	u32 rule_nb;

	// global var N_RULES has been initialized in update_lookup_index()
	
	for( i = candidate; i < N_RULES; i++ )
	{

		rule_nb = (u32) LOOKUP_INDEX[i];


		// performance strategy: 
		//  we check those values first that are most likely
		//  to give the most early and speedy result;
		//  especially strncmp() for d_iname is done at last, if at all
	

		/*  for debugging this little code snippet might help
		if( CURRENT->uid == 1000 ) 
			if( MAJOR( CURRENT->devID ) == 0x8 )
				if( CURRENT->d_iname[0] != '/' )
					printk("%s cmp [%u:%u] [%u:%u] [%X --- %X --- %X\n", CURRENT->d_iname, 
					MAJOR( CURRENT->devID ), MINOR( CURRENT->devID ),
					MAJOR( RT[rule_nb].devID ), MINOR( RT[rule_nb].devID ), CURRENT->devID, RT[rule_nb].devID, new_encode_dev(RT[rule_nb].devID) );
		*/

		// no ANY check for .devID since no wildcard allowed
		
		// From UserSpace Tool we give old style devID type, e.g. 801
		//
		// Internally, the Kernel does use a new u32 type, e.g. 800001
		//  (This is the type we get from pinode->i_sb->s_dev)
		//
		// So we need to have a transfer function to compare these two 
		// representations of one deviceID:
		//  see include/linux/kdev_t.h :
		//   static inline u32 new_encode_dev(dev_t dev)
		//   static inline dev_t new_decode_dev(u32 dev)
 		//

		if( MAJOR( CURRENT->devID ) != MAJOR( new_encode_dev(RT[rule_nb].devID) ) ) continue;
		if( MINOR( CURRENT->devID ) != MINOR( new_encode_dev(RT[rule_nb].devID) ) ) continue;
		

		if( RT_ANY_ALL(rule_nb) )
		{
			*rule_nb_match = rule_nb;		// early MATCH !

			return RULE_FOUND;			
		}
		

		if( ! RT_ANY_UID(rule_nb)   )	if( RT[rule_nb].uid != CURRENT->uid ) continue;

		if( ! RT_ANY_MASK(rule_nb) )
		{
			// we need to check for "!= RT[rule_nb].mask_required" after logic "&", since 
			// for mode 'a' we have 2 bits in .mask_required: MAY_WRITE and MAY_APPEND
			//    ... and just 1 bit in CURRENT->mask could give true after AND already
			//	  (that has to be avoided!)
			
			if( (RT[rule_nb].mask_required & CURRENT->mask) !=  RT[rule_nb].mask_required ) continue;
		
			if(  RT[rule_nb].mask_excluded & CURRENT->mask )  continue;
		}

		// for .i_mode:
		// since all possible .i_mode values are mutual exclusive,
		// we can test for exact match; first clear any bits outsite
		// S_IFMT(00170000) via "CURRENT->i_mode & S_IFMT"
		//
		// Note: Should we ever decide to use S_ISUID==0004000 or S_ISGID==0002000
		// then we need to _change_ this kind of check, since then it is no more exclusive:
		//  i_mode can be REGULAR and SUID at the same time, or a combination of DIRECTORY and SGID
		// (in fact, S_ISUID, S_ISGID, S_ISVTX are cleared away by "& S_IFMT" currently)


		if( ! RT_ANY_I_MODE(rule_nb) )	if( RT[rule_nb].i_mode != (CURRENT->i_mode & S_IFMT ) ) continue;
		
		if( ! RT_ANY_I_INO(rule_nb) )	if( RT[rule_nb].i_ino != CURRENT->i_ino ) continue;
		
		if( ! RT_ANY_I_UID(rule_nb) )	if( RT[rule_nb].i_uid != CURRENT->i_uid ) continue;
		
		if( ! RT_ANY_D_INAME(rule_nb) )
		{
			// do a quick compare for the 1st char:
			
			if( RT[rule_nb].d_iname[0] != CURRENT->d_iname[0] ) continue;
			
			// ..equal. so we have to compare completely:
			//  both strings are zero terminated, see
			//  secctl() and sanity_check_diname()
			
			if( strncmp( RT[rule_nb].d_iname, CURRENT->d_iname, SECCTL_DNAME_INLINE_LEN ) ) continue;
		}
		
		
		/////////////////////////////////////////
		// when we are here, there IS A MATCH !
		/////////////////////////////////////////
				
		*rule_nb_match = rule_nb;			// passing matching rule number to calling function

		return RULE_FOUND;			
	}

	return RULE_NOT_FOUND;
}



//
// intercept_sb_mount() is for informational purpose only
//  (we rely on intercept_sb_kern_mount() to assign MT.s_mntID and MT.psb)
//

/* from linuxsrc/include/security.h
 *
 * @sb_mount:
 *	Check permission before an object specified by @dev_name is mounted on
 *	the mount point named by @nd.  For an ordinary mount, @dev_name
 *	identifies a device if the file system type requires a device.  For a
 *	remount (@flags & MS_REMOUNT), @dev_name is irrelevant.  For a
 *	loopback/bind mount (@flags & MS_BIND), @dev_name identifies the
 *	pathname of the object being mounted.
 *	@dev_name contains the name for object being mounted.
 *	@path contains the path for mount point object.
 *	@type contains the filesystem type.
 *	@flags contains the mount flags.
 *	@data contains the filesystem-specific data.
 *	Return 0 if permission is granted.
 */

static int secctl_intercept_sb_mount(const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data )
{
	
	int	len1, len2;
	char	*pdev_name;
	char	*ptype;
	struct 	dentry	*pdentry, *p2dentry;
	

	if( secctl_locked == SECCTL_LOCKED_MOUNT )
	{
		printk("secctl: deny mount\n");
		return -EPERM;
	}
	

	// note: so far we don't care about flags like MS_REMOUNT or MS_BIND	
	
	pdev_name = (char*) dev_name;	if( pdev_name == NULL ) pdev_name = empty;
	
	ptype = (char*) type;		if( ptype == NULL ) ptype = empty;
	
	
	
	len1 = strnlen( pdev_name, MAX_DEV_NAME_LEN );
	len2 = strnlen( ptype, MAX_TYPE_LEN );
	

	memset( MT.dev_name, 0, MAX_DEV_NAME_LEN );
	strncpy( MT.dev_name, pdev_name, MAX_DEV_NAME_LEN );
	MT.dev_name[ MAX_DEV_NAME_LEN-1 ] = 0;

	memset( MT.type, 0, MAX_TYPE_LEN );
	strncpy( MT.type, ptype, MAX_TYPE_LEN );
	MT.type[ MAX_TYPE_LEN-1 ] = 0;


	//
	// retrieve path->dentry->d_iname
	//
	//  this is only informationally used in secctl_show_mounts();
	//  it will NOT be used for rule table or rule decision later on
	//

	memset( MT.d_iname, 0 , SECCTL_DNAME_INLINE_LEN );
	
	if( path != NULL )
	{
		if( path->dentry != NULL )
		{
			pdentry = path->dentry;
			
			//
			// howto lock this dentry: see explanation above in secctl()
			//
			
			p2dentry = dget( pdentry );

			if( p2dentry->d_iname )
			{			
				if( p2dentry->d_iname[0] != 0 )
				{
					strncpy( MT.d_iname,
					 p2dentry->d_iname, SECCTL_DNAME_INLINE_LEN );

					MT.d_iname[ SECCTL_DNAME_INLINE_LEN-1 ] = 0;
				}
			}
			
			dput( p2dentry );
		}
	}
	
	
	MT.flags = flags;
	
	
	//
	// the overall mount process need to call
	//   sb_kern_mount()
	// such that we assign
	//   MT.status = USED;
	//
	// if the overall mount process does not call sb_kern_mount()
	// (like subsequent UNIONFS/usr of UNIONFS/home mounts)
	// then this MT entry will be overwritten before sb_kern_mount()
	// has a chance to complete MT
	//

	return 0;
	
}


static u32 global_mntID = 0;


static int secctl_intercept_sb_kern_mount( struct super_block *sb, int flags, void *data )
{
	char *d_iname;
	char *dev_name;
	char *type;
	int len;

	if( secctl_locked == SECCTL_LOCKED_MOUNT )
	{
		printk("secctl: deny kern_mount\n");
		return -EPERM;
	}



	MT.s_mntID = global_mntID++;

	MT.psb = sb;
	
	MT.s_magic = sb->s_magic;
	
	MT.devID = sb->s_dev;

		
	if( sb->s_id )
	{
		memcpy( MT.s_id, sb->s_id, 32 );
		MT.s_id[32] = 0x0;
	}
	else
	{
		len = strnlen(empty,32);				// empty is constant string
		memcpy( MT.s_id, empty, len );		// len <= 32 anycase
		MT.s_id[len] = 0x0;
	}

	
	MT.status = USED;

	//////// verbose print /////////////////////////////////////

	d_iname = empty;

	if( MT.d_iname[0] != 0 )
	{
		d_iname = MT.d_iname;
	}

	dev_name = empty;

	if( MT.dev_name[0] != 0 )
	{
		dev_name = MT.dev_name;
	}

	type = empty;

	if( MT.type[0] != 0 )
	{
		type = MT.type;
	}

	// dev_name, d_iname and type were safely zero-terminated 
	// in secctl_intercept_sb_mount()

	printk("secctl: kern_mount %3d %6X %10lX %16.32s %14.32s %14.40s %14.32s %6lX\n",
		MT.s_mntID, (u32)new_decode_dev(MT.devID), MT.s_magic, 
		MT.s_id, dev_name, d_iname, type, MT.flags );


	return 0;
}



static int secctl_intercept_sb_umount( struct vfsmount *mnt, int flags )
{
	if( secctl_locked == SECCTL_LOCKED_MOUNT )
	{
		printk("secctl: deny umount\n");
		return -EPERM;
	}

	return 0;
}


static int secctl_intercept_sb_remount( struct super_block *sb, void *data)
{
	if( secctl_locked == SECCTL_LOCKED_MOUNT )
	{
		printk("secctl: deny remount\n");
		return -EPERM;
	}

	return 0;
}


static struct security_operations secctl_ops = {
	.name =				"secctl",
	
	.sb_kern_mount = 		secctl_intercept_sb_kern_mount,
	.sb_mount = 			secctl_intercept_sb_mount,
	.sb_umount =	 		secctl_intercept_sb_umount,
	.sb_remount =	 		secctl_intercept_sb_remount,
	
	.inode_permission =		secctl_intercept_inode_permission,	
	.inode_unlink = 		secctl_intercept_inode_unlink,
	.inode_rename = 		secctl_intercept_inode_rename,
	.inode_setattr= 		secctl_intercept_inode_setattr,
	.inode_rmdir  = 		secctl_intercept_inode_rmdir, 
	.inode_link   = 		secctl_intercept_inode_link,
		
	.bprm_check_security =  	secctl_intercept_bprm_check,

};
	


// credits to apparmor: secctl_enabled_setup() and parts of secctl_init()
//	are adapted from apparmor/lsm.c


/* Flag indicating whether initialization completed */
int secctl_initialized __initdata;


/* Boot time disable flag */
static unsigned int secctl_enabled = CONFIG_SECURITY_SECCTL_BOOTPARAM_VALUE;

static int __init secctl_enabled_setup(char *str)
{
	unsigned long enabled;
	int error = strict_strtoul(str, 0, &enabled);
	if (!error)
		secctl_enabled = enabled ? 1 : 0;
	return 1;
}

__setup("secctl=", secctl_enabled_setup);




static int __init secctl_init(void)
{
	int error;


	// compile-time check :

	BUILD_BUG_ON( sizeof(RULE_TABLE_ENTRY) != (RULE_TABLE_ENTRY_EXPECTED_SIZE ) );

	// runtime-time check :
	
	error = sanity_validate_size_of_RTE();
	
	if(error) return -1;
	

	////////////////////////////////////////////
	// register secctl

	if (!secctl_enabled || !security_module_enable(&secctl_ops)) {
		printk("secctl: disabled by boot time parameter.\n");
		secctl_enabled = 0;
		return -1;
	}

	error = register_security(&secctl_ops);
	if (error) {
		printk("secctl: unable to register lsm.\n");
		return -2;
	}

	//////////////////////////////////////////////////
	// alloc space for global rule table RT[]
	
	RT = (RULE_TABLE_ENTRY*) kmalloc( RT_MAX * sizeof( RULE_TABLE_ENTRY ), GFP_KERNEL );
	
	if( !RT )
	{
		printk("secctl: init() FAILED to kmalloc(RT[]) !\n");
		return -4;
	}
	
	secctl_clear_rules();

	//////////////////////////////////////////////////
	// alloc space for global lookup index
	
	LOOKUP_INDEX = (u16*) kmalloc( RT_MAX * sizeof( u16 ), GFP_KERNEL );
	
	if( !LOOKUP_INDEX )
	{
		printk("secctl: init() FAILED to kmalloc(LOOKUP_INDEX[]) !\n");
		return -5;
	}

	//////////////////////////////////////////////////

	memset( &MT, 0, sizeof(MOUNT_TABLE_ENTRY) );
	
	

	printk("secctl: init() done.\n");

	secctl_initialized = 1;


	
	return 0;

}

security_initcall(secctl_init);



// print all rules from RT[] to syslog via printk()
// 
// Any single rule is printed by just one call to printk()
//
// We take utmost care that there are no format or overflow issues;

// no single dynamic argument to printk() can be longer than this:
#define ARG_BUF_LEN	32

static void secctl_printk_rules(void)
{
	int at_least_one;

	u32  n;				// rule number
	
	char *str_policy;
	char str_nb[ARG_BUF_LEN];
	char str_uid[ARG_BUF_LEN];
	char str_mask[ARG_BUF_LEN];
	char str_devID[ARG_BUF_LEN];
	char str_i_ino[ARG_BUF_LEN];
	char str_i_uid[ARG_BUF_LEN];
	char str_i_mode[ARG_BUF_LEN];
	
	char str_d_iname[SECCTL_DNAME_INLINE_LEN];

	at_least_one = 0;


	printk("secctl: --- show rules:\n");
	printk("secctl: rule | policy | uid | mask | devID | i_ino | i_uid | i_mode | d_iname\n");


	// not performance critical; so we need not use LOOKUP_INDEX[] like in find_match()

	for( n=0; n<RT_MAX; n++ )
	{
		if( ! RT_USED(n) ) continue;
		
		sprintf(str_nb,"%u", n );

		if( RT_LOGGING(n) )
		{
			str_policy = (RT_POLICY_ACCEPT(n)) ? "accept+" : "  deny+";			
		}
		else
		{
			str_policy = (RT_POLICY_ACCEPT(n)) ? "accept " : "  deny ";
		}

		if( RT_ANY_UID(n) )	
			sprintf(str_uid,"*");
		else
			sprintf(str_uid,"%u", RT[n].uid );

		if( RT_ANY_MASK(n) )
			sprintf(str_mask," *  ");
		else
			sprintf(str_mask,"0x%02X", RT[n].mask );

		sprintf(str_devID,"0x%X", RT[n].devID );

		if( RT_ANY_I_INO(n) )
			sprintf(str_i_ino,"*");
		else
			sprintf(str_i_ino,"%lu", (long unsigned int)RT[n].i_ino );

		if( RT_ANY_I_UID(n) )
			sprintf(str_i_uid,"*");
		else
			sprintf(str_i_uid,"%u", RT[n].i_uid);

		if( RT_ANY_I_MODE(n) )
			sprintf(str_i_mode,"*");
		else
			sprintf(str_i_mode,"0%o", (u32)RT[n].i_mode );

		if( RT_ANY_D_INAME(n) )
			sprintf(str_d_iname,"*");
		else
		{
			// although this .diname in our RULE TABLE should come from trusted input,
			// we better sanitize first..
			
			sanitize_diname( RT[n].d_iname, SECCTL_DNAME_INLINE_LEN );

			sprintf(str_d_iname, "%.*s", SECCTL_DNAME_INLINE_LEN-1, RT[n].d_iname );
		}

		str_nb[ARG_BUF_LEN-1] = 0;
		str_uid[ARG_BUF_LEN-1] = 0;
		str_mask[ARG_BUF_LEN-1] = 0;
		str_devID[ARG_BUF_LEN-1] = 0;
		str_i_ino[ARG_BUF_LEN-1] = 0;
		str_i_uid[ARG_BUF_LEN-1] = 0;
		str_i_mode[ARG_BUF_LEN-1] = 0;
		
		str_d_iname[SECCTL_DNAME_INLINE_LEN-1] = 0;


	// note: we use precision specifiers for MAXIMUM len of string 
	//
	// e.g.	.policy		max. 7 chars	("%.7s")			(fixed len)
	// or	.d_iname	max. SECCTL_DNAME_INLINE_LEN-1 chars ("%.*s")	(len set by const)
	//
	//                       nb  pol   uid  mask mnt   ino  iuid imode dname

		printk("secctl: %.5s %.7s %.10s %.4s %.10s %.20s %.10s %.7s %.*s\n",
			str_nb, str_policy, str_uid, str_mask, str_devID,
			str_i_ino, str_i_uid, str_i_mode,
			SECCTL_DNAME_INLINE_LEN-1, str_d_iname );

		at_least_one = 1;
	}
	
	if( ! at_least_one )
	{
		printk("secctl: RT[] empty!\n");
	}
}




static void secctl_clear_rules(void)
{
	int n;

	for( n=0; n<RT_MAX; n++ )
	{
		RT[ n ].bitfield = UNUSED;
	}
}


//
// called right before the kernel lsm is switched "on"
// ( CMD_LSM_ON )
//

static void update_lookup_index(void)
{
	u32 index_rt;	// index rule table
	u32 index_li;	// index lookup index

	N_RULES = 0;
	
	index_li = 0;

	for( index_rt=0; index_rt<RT_MAX; index_rt++ )
	{
		if( RT_USED(index_rt) )
		{
			LOOKUP_INDEX[ index_li++ ] = (u16) index_rt;
			
			N_RULES++;
			
			// global var N_RULES will be used in find_match*()
			// when secctl() is called from any lsm hook later on
		}
	}
}




static void secctl_log( RULE_TABLE_ENTRY *CURRENT )
{
	char *policy;
	char *oops	 	= "Oops";
	char *policy_accept	= "ACCEPT";
	char *policy_deny	= "_DENY_";
	char  *which_hook;
	
	policy = oops;		// safely initialize pointer
				// (see "exception" in secctl())
	
	if( CURRENT->bitfield & POLICY_ACCEPT )	policy = policy_accept;
	if( CURRENT->bitfield & POLICY_DENY ) 	policy = policy_deny;

	
	switch( CURRENT->which_hook )
	{
		case HOOK_BPRM_CHECK: 		which_hook = hook_str_bprm;  break;
		case HOOK_INODE_PERMISSION:	which_hook = hook_str_perm;  break;
		case HOOK_INODE_UNLINK:		which_hook = hook_str_unlk;  break;
		case HOOK_INODE_RENAME:		which_hook = hook_str_renm;  break;
		case HOOK_INODE_SETATTR:	which_hook = hook_str_seta;  break;
		case HOOK_INODE_RMDIR:		which_hook = hook_str_rmdr;  break;
		case HOOK_INODE_LINK:		which_hook = hook_str_link;  break;
		
		default:			which_hook = oops;

	}

	if( printk_logging )
	{
		sanitize_diname( CURRENT->d_iname, SECCTL_DNAME_INLINE_LEN );
	
		// note: .account does contain "jiffies" time information 
		
		// note: we use precision specifiers for max. len of string
		//	.policy		max. 7 chars
		//	.d_iname	max. SECCTL_DNAME_INLINE_LEN-1 chars
		//	.which_hook	max. 4 chars
		//	to be printed via printk()
			
		printk_ratelimited( "secctl: %3u %.7s %u 0x%X 0x%X %lu %u 0%o %.*s [%.4s]\n",
			(u32)CURRENT->rule_nb,
			policy, 
			(u32)CURRENT->uid,
			(u32)CURRENT->mask,
			(u32)CURRENT->devID,
			(long unsigned int)CURRENT->i_ino,
			(u32)CURRENT->i_uid,
			(u32)CURRENT->i_mode,
			SECCTL_DNAME_INLINE_LEN-1,	// precision specifier '%.*s' for max. string-len of d_iname;
			CURRENT->d_iname,		// additionally, string *d_iname was safely terminated in secctl()
			which_hook );
	}
}






/************************************* control functions for /dev/secctl ******************************************/

static int callback_open( struct inode *i, struct file *f );
static ssize_t callback_read(struct file *f, char __user *buf, size_t len, loff_t *ptr);
static int callback_read_rule_table_entry(struct file *f, char __user *buf, size_t len, loff_t *ptr);
static ssize_t callback_write(struct file *f, const char __user * buf, size_t len, loff_t *ppos);
static int callback_release( struct inode *i, struct file *f );

static int __init device_init(void);

static int device_opened = 0;

spinlock_t open_lock;	// initialized in device_init()

extern int secctl_modules_disabled;			// see kernel/modules.c (modified)


static const struct file_operations fops = {
	.open  = callback_open,
	.read  = callback_read,
	.write = callback_write,
	.release = callback_release,
};


static int __init device_init()
{
	int rc;
	

	printk("secctl: device_init(%s)\n", SECCTL_DEVICE );
	
	rc = register_chrdev( SECCTL_DEVICE_MAJOR, SECCTL_DEVICE, &fops );

	if( rc < 0 )
	{
		printk("secctl: device_init(): register_chrdev() failed with error %d !\n", rc );
	}

	spin_lock_init( &open_lock );		// for callback_open()
	
	return rc;
}

module_init(device_init);


// for function callback_read_rule_table_entry():
// When reading rules via /dev/secctl later on,
//  we will start with RT[ SEEK_POS_READ_RULE ]
// This seek pos will be init. by callback_open()

static u32 SEEK_POS_READ_RULE;



// when UserSpace calls open("/dev/secctl", # );
//
// we make sure just _one_ process can open this device at the same time:
//
//  We expect one <secctl> UserSpace admin tool active at a time.
//  So the second <secctl> UserSpace admin tool does receive -EBUSY when
//  trying to open /dev/secctl a second time (when the first <secctl> 
//  process has it still open)
//
// Nevertheless, to avoid race condition TOCTOU when multiple processes would 
// access global var <device_opened>, we better use a spinlock <open_lock>
//
// Without this restriction, we would probably need locks for our global SEEK_POS_* 
// vars as well.
//
// Note:
//  If the kernel would serialize open() calls from several processes,
//  we would probably not need this spin_lock (we assume the kernel
//  does not serialize)
//  

static int callback_open( struct inode *i, struct file *f )
{
	int rc;



	if( secctl_locked )
	{
		// If we are locked, check whether the user did wait long enough;
		//
		// Current jiffies need to be greater than our previously set
		// var <lock_wait_for_jiffie[32|64]> to proceed with open().
		// If not, then we return -BUSY to UserSpace.
		// 
		// We deny open() already when the wait period was not over.
		// This is a security precaution. 
		//
		// Alternatively one could open(), read the packet, then check .cmd,
		// and finally compare current jiffies. But this would require a lot of
		// packet processing although we are in state secctl_locked.
		// Not a good idea. That's why we check early and deny open() if
		// the wait period is not over.
		//
		// no spinlock seems necessary since we access these vars readonly

		BUILD_BUG_ON( (sizeof(jiffies) != 4) && (sizeof(jiffies) != 8) );

		if( sizeof( jiffies ) == 8 )
		{
			if( jiffies < lock_wait_for_jiffie64 )
			{
				DEBUG( printk("secctl: open(): deny unlock attempt\n"); )

				return -EBUSY;
			}
		}
		else
		{
			// should work also when both 32 bit values do overflow;
			// But this is NOT tested (we did test only on 64 kernel!)

			if( jiffies < lock_wait_for_jiffie32 )
			{
				DEBUG( printk("secctl: open(): deny unlock attempt\n"); )

				return -EBUSY;
			}
		}
	}


	// spinlock because of TOCTOU for global var <device_opened>
	
	
	spin_lock( &open_lock );		// <---------- lock START

	if( device_opened )
	{
		rc = -EBUSY;
	}
	else
	{
		device_opened = 1;

		SEEK_POS_READ_RULE = 0;

		rc = 0;
	}
	
	spin_unlock( &open_lock );		// <---------- lock END


	DEBUG( if( rc ) printk("secctl: open() BUSY\n"); )
	DEBUG( if( ! rc ) printk("secctl: open() OK\n"); )
	
	
	return rc;
}


// when UserSpace calls close(fd);
//
// need no locking here, since we made sure that there is only
// one process that has opened /dev/secctl (see callback_open())

static int callback_release( struct inode *i, struct file *f )
{


	DEBUG( printk("secctl: close()\n"); )

	device_opened = 0;
	
	return 0;
}




// when UserSpace calls read( fd, &RTE, sizeof(RTE) ):
// 
// rc:  >= 0 : bytes written to UserSpace
//	 < 0 : if error
//
// we have one read modus (set by callback_write to global var <callback_readmode>)
//
// CMD_LSM_SHOW_RULES: put valid rules in RT[] to UserSpace
//

static ssize_t callback_read(struct file *f, char __user *buf, size_t len, loff_t *ptr)
{
	int rc;



	if( secctl_locked )
	{
		DEBUG( printk("secctl: read() LOCKED!\n"); )

		return -EINVAL;
	}

	if( ! device_opened )
	{
		// should not happen anyway, since UserSpace does not have
		// a file descriptor without calling open() first
		
		DEBUG( printk("secctl: read() NOT OPENED\n"); )

		return -EINVAL;
	}
	
	DEBUG( printk("secctl: read(.., len=%u ) ... (cmd = 0x%X )\n", (unsigned int)len, callback_readmode ); )
	
	rc = -EINVAL;
	
	switch( callback_readmode )
	{
		case CMD_LSM_SHOW_RULES: 
		
			if( N_RULES >= 0 )
			{
				rc = callback_read_rule_table_entry(f,buf,len,ptr);
			}
			
			break;
		
		/* We used to have more read modi here for debug purposes;
		 * That's why we have a switch statement here;
		 */
	}
	
	return (ssize_t) rc;
}


// called from callback_read()
// UserSpace wants to read an entry from RT[]
// (exactly one entry RTE for one read() call)
//
// we use global seek position <SEEK_POS_READ_RULE> to keep track 
// which entry from RT[] is to be read next;
// <SEEK_POS_READ_RULE> is safely initialized (=0) in callback_open()
//
// rc:
//	> 0 (#nbytes) put successfully to UserSpace (== sizeof(RULE_TABLE_ENTRY))
//	== 0 if end of array reached (nbytes is zero then)
//	< 0 if failure or param #len != sizeof(RULE_TABLE_ENTRY)
//

static int callback_read_rule_table_entry(struct file *f, char __user *buf, size_t len, loff_t *ptr)
{
	u32 rule, n, nbytes;
	int err;
	u8 *pbyte;
	
	if( len != sizeof(RULE_TABLE_ENTRY) ) return -EINVAL;

	DEBUG( printk("secctl: read_rule_table()...RT[%u]\n", SEEK_POS_READ_RULE ); )
	
	nbytes = 0;

	if( SEEK_POS_READ_RULE < 0 ) return -EINVAL;		// should not be

	for( rule=SEEK_POS_READ_RULE; rule<RT_MAX; rule++ )
	{
		// one rule:
		
		if( RT_USED(rule) )
		{
			(void) secctl_calc_RTE_checksum( &RT[rule] );
			
			pbyte = (u8*) &RT[rule];

			DEBUG( printk("secctl: read_rule_table() copy rule %d ..\n", rule ); )
		
			for( n=0; n < (u32)sizeof(RULE_TABLE_ENTRY); n++ )
			{
				err = put_user( *(pbyte++), buf++ );
				
				if( err ) return -EINVAL;
				
				nbytes++;
			}
			
			SEEK_POS_READ_RULE = rule + 1;	// for next read() call
			
			break;				// DONE. One rule has been transfered to UserSpace.
		}					// UserSpace needs to call read() again to get next rule
	}

	// we can safely cast u32 -> int, since nbytes 
	// is 0 or equal sizeof(RULE_TABLE_ENTRY) which is well inside 0..2^31
	
	return (int)nbytes;		
}



// when UserSpace calls write( fd, &RTE, sizeof(RTE) );
// 
// we read from UserSpace: exactly #sizeof(RULE_TABLE_ENTRY) bytes at a time !
//
// For multiple rules, we expect UserSpace to call write( .. &RTE) multiple times!
// (reading rules from UserSpace is not a performance critical issue)
//
// For all other CMD_* a single RTE packet is sufficient.
//
// rc:
//  either #sizeof(RULE_TABLE_ENTRY) if reading one packet RTE was OK
//	   (we trust the compiler to cast (size_t) size_RTE --> (ssize_t)
//
//  or  -EINVAL || -EPERM

static ssize_t callback_write(struct file *f, const char __user *buf, size_t len, loff_t *ppos)
{
	u32 i,	nbytes;
	size_t	size_RTE;
	int	err;
	int	equalbytes;
	u8	*pbyte;
	u32	checksum;

	RULE_TABLE_ENTRY  RTE;
	
	static u32	unlock_wait_factor = 1;
	static u8	lock_passwd[ SECCTL_DNAME_INLINE_LEN ];



	DEBUG( printk("secctl: callback_write( len=%u ... )\n", (unsigned int)len ); )

	size_RTE = sizeof(RULE_TABLE_ENTRY);

	if( len != size_RTE ) return -EINVAL;

	
	memset( &RTE, 0, size_RTE );	// anyway..
	
	nbytes = 0;

	pbyte = (u8*) &RTE;					// <---------- read into temp. local RTE
	
	for( i=0; i<size_RTE; i++ )
	{
		err = get_user( *(pbyte++), buf++ );
		
		if( err ) return -EINVAL;
		
		nbytes++;
	}
	
	// double-check:
	// we insist on reading exactly one RTE block
	//
	
	if( nbytes != (u32)size_RTE ) return -EINVAL;


	// re-calc integrity .checksum first:

	checksum = RTE.checksum;
	
	if( checksum != secctl_calc_RTE_checksum( &RTE ) )
	{
		return -EINVAL;
	}

	// If there was any error above, we did silently return.
	// In particular, we did not printk() any error message
	// until we are safely in unlocked mode below..
	//  (when we were locked)
	
	DEBUG( printk("secctl: write() RTE.cmd = 0x%X\n", (u32) RTE.cmd ); )
	
	//
	// handle unlocking first if already locked
	//

	if( secctl_locked )
	{
		// Note: we have checked in callback_open() already that our wait period was over now.
		//	So we did accept this new RTE packet, and will check now if it has the right .cmd
		//	and the right unlock password in .diname[]
		
	
		if( RTE.cmd == CMD_LSM_UNLOCK )
		{
			// for comparison use always the same amount of time
			// (do not break out early at the first "!=")

			equalbytes = 0;

			for(i=0; i<SECCTL_DNAME_INLINE_LEN; i++)
			{
				if( (u8)RTE.d_iname[i] == lock_passwd[i] ) equalbytes++;
				else equalbytes--;
			}

			DEBUG( printk("secctl: equalbytes = %d\n", equalbytes ); )

			if( equalbytes == SECCTL_DNAME_INLINE_LEN )
			{
				secctl_locked = SECCTL_UNLOCKED;
				
				unlock_wait_factor = 1;

				printk("secctl: unlocked.\n");

				return size_RTE;
			}

			
			// ..wrong password: then we increase wait time counter
			// for next unlock attempt to be accepted, re-starting waiting 
			// from _current_ jiffies
			// maximum (SECCTL_UNLOCK_WAIT_SECONDS * unlock_wait_factor) is 10 * 6 = 60 seconds

			if( unlock_wait_factor < 6 ) unlock_wait_factor++;

			DEBUG( printk("secctl: unlock wait: %u x %u seconds\n", SECCTL_UNLOCK_WAIT_SECONDS, unlock_wait_factor ); )

			if( sizeof( jiffies ) == 8 )
			{
				lock_wait_for_jiffie64 = jiffies + HZ * SECCTL_UNLOCK_WAIT_SECONDS * (u64)unlock_wait_factor;
			}
			else
			{
				lock_wait_for_jiffie32 = jiffies + HZ * SECCTL_UNLOCK_WAIT_SECONDS * unlock_wait_factor;

				// this 32 bit var can overflow, 
				// then jiffies will overflow shortly as well
				//
				// Note: 32bit kernel is _not_ tested.
			}

		}

		return -EINVAL;		// silently return if wrong passwd
					// or other RTE.cmd

	}
	
	// unlocked mode. 

	switch( RTE.cmd	)
	{

		case CMD_LSM_SET_RULE:
		
			if( secctl_active )
			{
				printk("secctl: is <on> ! First disable secctl to set new rule!\n");
			
				return -EPERM;
			}
			
			//
			// do check if temporary RTE does meet our expectations
			//  (is it a valid rule ?)
			
			err = sanity_check_RTE( &RTE );
			
			if( err ) return -EINVAL;
	
			// OK: seems to be a rule with valid attributes
			//  now copy temp RTE to global RT[]
	
			memcpy( &RT[ RTE.rule_nb ], &RTE, size_RTE );
	
			printk("secctl: new rule %d INSERTED.\n", RTE.rule_nb );
			
			
			return size_RTE;	
			

		case CMD_LSM_ON:

			if( secctl_active == 1 ) return size_RTE;	// do not switch "on" again

		
			// switch "on" only if we have at least one rule in RT[]
		
			update_lookup_index();				// will update global var N_RULES
			
			if( N_RULES > RT_MAX )
			{
				printk("secctl: error: NRULES > RT_MAX\n");
				
				return -EINVAL;
			}
			
			
			if( N_RULES > 0 )
			{
				secctl_active = 1;

				printk("secctl: on.\n");
			}
			else
			{		
				printk("secctl: not enabled since no valid rules!\n");
				
				return -EINVAL;
			}
			
			return size_RTE;
	

		case CMD_LSM_OFF:

			if( secctl_active == 0 ) return size_RTE;	// do not switch "off" again


			secctl_active = 0;

			printk("secctl: off.\n");
			
			return size_RTE;


		case CMD_LSM_DEFAULT_POLICY_ACCEPT:

			if( secctl_active )
			{
				printk("secctl: is <on> ! First disable secctl to change policy!\n");
			
				return -EPERM;
			}

			SECCTL_DEFAULT = SECCTL_ACCEPT;

			printk("secctl: default policy ACCEPT.\n");
				
			return size_RTE;

		case CMD_LSM_DEFAULT_POLICY_DENY:

			if( secctl_active )
			{
				printk("secctl: is <on> ! First disable secctl to change policy!\n");
			
				return -EPERM;
			}

			SECCTL_DEFAULT = SECCTL_DENY;

			printk("secctl: default policy DENY.\n");
				
			return size_RTE;

		case CMD_LSM_PRINTK_RULES:
		
			// can be done regardless of secctl_active or not,
			// since we just _read_ from RT[]
		
			secctl_printk_rules();

			return size_RTE;

		case CMD_LSM_SHOW_RULES:

			// can be done regardless of secctl_active or not,
			// since we just _read_ from RT[]
			
			// global var <callback_readmode> will be used in callback_read() 
			// when userspace later calls fopen(SECCTL_DEVICE) and does read(SECCTL_DEVICE)
			// to actually retrieve rules from RT[] then
		
			callback_readmode = CMD_LSM_SHOW_RULES;
			
			return size_RTE;

		case CMD_LSM_CLEAR_RULES:

			if( secctl_active )
			{
				printk("secctl: is <on> ! First disable secctl to clear rules!\n");
			
				return -EPERM;
			}

			secctl_clear_rules();

			printk("secctl: all rules cleared.\n");

			return size_RTE;

		case CMD_LSM_DEBUG_SIZE_TEST:

			secctl_print_sizeof();

			return size_RTE;


		case CMD_LSM_LOCK:
		case CMD_LSM_LOCKM:

			if( RTE.cmd == CMD_LSM_LOCK )  secctl_locked = SECCTL_LOCKED;
			if( RTE.cmd == CMD_LSM_LOCKM ) secctl_locked = SECCTL_LOCKED_MOUNT;


			memcpy( lock_passwd, (u8*) RTE.d_iname, SECCTL_DNAME_INLINE_LEN );			


			printk("secctl: locked.\n");


			if( sizeof( jiffies ) == 8 )
			{
				lock_wait_for_jiffie64 = jiffies + HZ * SECCTL_UNLOCK_WAIT_SECONDS * unlock_wait_factor;
			}
			else
			{
				lock_wait_for_jiffie32 = jiffies + HZ * SECCTL_UNLOCK_WAIT_SECONDS * unlock_wait_factor;

				// this 32 bit var can overflow, 
				// then jiffies will overflow shortly as well
			}

			// Note: we will check in callback_open() whether this wait period was over then
			
			return size_RTE;
			
			
		case CMD_LSM_UNLOCK:	// if not locked, but unlock cmd sent
		
			return size_RTE;
			
		
		default: printk("secctl: unknown .cmd 0x%X\n", RTE.cmd );
	}
	
	return -EINVAL;
}


// 
// validate input from UserSpace
//  called from callback_write()
//
// validation strategy: we do whitelist checks; any combination
// that does not fit into our explicit expectation, is rejected
// with -EINVAL
//
// integrity RTE.checksum was validated by calling function
//
// note: .bitfield does overrule .value
//
// rc:	0 if OK
//	# if not OK
//

static int sanity_check_RTE( RULE_TABLE_ENTRY *pRTE )
{
	int err;
	u16 tmp;

	
	/*  RULE_TABLE_ENTRY:

	check
	nb.
	1	u32		uid;
	2	u8		mask;
	3	u8		mask_required;
	4	u8		mask_excluded;

	5	u8		cmd;		
	6	u16		rule_nb;	
	7	u16		bitfield;	
	
	8	u32 		devID;	
	9	u64 		i_ino;		
	10	u32		i_uid;		
	11	u16		i_mode;
	11a	u8		which_hook;
	11b	u8		d_iname_len;

	12	char		d_iname[ SECCTL_DNAME_INLINE_LEN ];
	13	u32		account;	
	14	u32		checksum;

	u16	i_mode;		// of the inode	(umode_t)			u16	2
	u8	which_hook;	// for logging which hook called us		u8	1
	u8	d_iname_len;	// unused; could speed up strncmp in future	u8	1	

	note: we check >= 0 and <= MAX for unsigned values,
	 although any case outside these bounds shouldn't happen for u**

	*/


	// check 14 : checksum was already verified by calling function

	// check 1

	if( !( (pRTE->uid >=0) && (pRTE->uid <= U32_MAX) ) ) return -EINVAL;

	//  uid can be any value whether ANY_UID bit set or not (0 is valid UID)


	// check 2,3,4

	/*****************************************
	from $kernel/include/linux/fs.h 
	#define MAY_EXEC		0x00000001 
	#define MAY_WRITE		0x00000002 
	#define MAY_READ		0x00000004 
	#define MAY_APPEND		0x00000008 
	#define MAY_ACCESS		0x00000010 
	#define MAY_OPEN		0x00000020 
	#define MAY_CHDIR		0x00000040 
	#define MAY_NOT_BLOCK		0x00000080 
	******************************************/
	
	/******************************************************
	  access mask overview, later enforced in find_match()
	
	access	ANY_	required bits	excluded bits
	 type	 MASK	in one hook	in this hook
	 	bit	.mask		.mask
	----------------------------------------------
	x	-	MAY_EXEC	MAY_READ |
					MAY_WRITE |
					MAY_APPEND
			
	l	-	<like x, for special case ld.so:
			if calling hook is bprm (exec syscall)
			then deny, else allow (if match)>
	
			
	r	-	MAY_READ	MAY_EXEC |
					MAY_WRITE |
					MAY_APPEND
	
	w	-	MAY_WRITE	MAY_EXEC |
					MAY_READ
	
	a	-	MAY_WRITE &	MAY_EXEC |
			MAY_APPEND	MAY_READ

	*	set	<don't care>	<don't care>
	

	notes:
	0) This policy needs to be compatible with any .mask that
	   comes with a single inode_permission hook; Any accept or
	   deny decision (find_match()) is being made for any 
	   single hook on its own. The kernel passes only
	   specific bit-combinations to the inode_permission hook!
	   In particular, MAY_READ and MAY_WRITE seem _not_ to
	   come with one hook. The kernel instead does generate two
	   separate hook calls. We follow this policy consequently
	   by setting MAY_READ in "excluded bits" for "w" and "a".
	   That means:
	   For 'w' and 'a' access types, MAY_READ is _not_ allowed.
	   Instead do use a second rule to implement e.g. 
	   MAY_WRITE _and_ MAY_READ for _one_ object, or
	   MAY_APPEND _and_ MAY_READ for _one_ object.
	1) We do only check for bits required and excluded;
	   so we don't check for MAY_OPEN and MAY_ACCESS
	2) We do not care about MAY_CHDIR and MAY_NOT_BLOCK.
	   In particular, directory access is handled with 'x'
	   already.
	3) For 'a' access type _no_ write operation is permitted 
	   before the end of file (MAY_WRITE could suggest this).
	   For 'a' we use "|" to set WRITE and APPEND bits here;
	   for later permission check in find_match() we expect 
	   both bits in _one_ hook .mask for an "append" access
	   to an object (generated by the kernel this way)
	5) For 'x' : no read, write or append is allowed; (The
	   kernel does use another way to "read" the executable.)
	   If you want one of these additional permissions,
	   then do use more rules for read, write or append.
	*******************************************************/

	pRTE->mask_required = 0;
	pRTE->mask_excluded = 0;
	
	// from UserSpace, we just expect setting .mask to one 
	// of 5 values: *,x,r,w,a
	// typecast to (u8) from 32bit MAY_* constants is neccessary
	// since pRTE->mask* is u8 (we use the lower 8 bits only)
	
	pRTE->bitfield &= ~ANY_MASK;	// clear ANY_MASK bit
					// set only for case '*'
	
	switch( pRTE->mask )
	{
		case '*':	pRTE->bitfield |= ANY_MASK;
				break;

		case 'l':
		case 'x':	pRTE->mask_required = (u8)MAY_EXEC;
				pRTE->mask_excluded = (u8)MAY_READ  | (u8)MAY_WRITE | (u8)MAY_APPEND;
				break;

		case 'r':	pRTE->mask_required = (u8)MAY_READ;
				pRTE->mask_excluded = (u8)MAY_EXEC  | (u8)MAY_WRITE | (u8)MAY_APPEND;
				break;

		case 'w':	pRTE->mask_required = (u8)MAY_WRITE;
				pRTE->mask_excluded = (u8)MAY_EXEC  | (u8)MAY_READ;
				break;

		case 'a':	pRTE->mask_required = (u8)MAY_WRITE | (u8)MAY_APPEND;
				pRTE->mask_excluded = (u8)MAY_EXEC  | (u8)MAY_READ;
				break;
				
		default:	return -EINVAL;
	}
	// pRTE->mask does not matter anymore in KernelSpace, since find_match()
	// will only use RT[].mask_required and RT[].mask_excluded
	//
	// Later, CURRENT.mask will be logged as received from calling hook,
	// can either be one of [xrwa] or another hex value as combination of poss. values


	// check 5
	
	pRTE->cmd = 0;		// reset to 0


	// check 6

	if( !( (pRTE->rule_nb >= 0) && (pRTE->rule_nb < RT_MAX) ) ) return -EINVAL;


	// check 7

	/*******************************************************************
	  check .bitfield for combinations that make sense
	  
	  USED			0x0001  must be set
	  POLICY_ACCEPT		0x0002  [ either..
	  POLICY_DENY		0x0004   ..or ]
	  LOGGING		0x0008  set or not (don't check)
	
	<any combination of ANY_ is allowed>
		
	  ANY_UID		0x0010
	  ANY_MASK		0x0020
	  ANY_I_INO		0x0040
	  ANY_I_UID		0x0080
	  ANY_I_MODE		0x0100
	  ANY_D_INAME		0x0200
	***********************************************************************/

	if( !( pRTE->bitfield & USED ) ) return -EINVAL;
	
	tmp = pRTE->bitfield & (POLICY_ACCEPT | POLICY_DENY);
	if( (tmp != POLICY_ACCEPT) && (tmp != POLICY_DENY) ) return -EINVAL;

	// check 8

	if( !( (pRTE->devID >= 0x0) && (pRTE->devID <= U32_MAX ) ) ) return -EINVAL;


	// check 9

	if( !( (pRTE->i_ino >= 0x0) && (pRTE->i_ino <= U64_MAX ) ) ) return -EINVAL;
	
	if( (pRTE->bitfield & ANY_I_INO) && (pRTE->i_ino > 0x0) ) return -EINVAL;
	

	// check 10

	if( !( (pRTE->i_uid >= 0x0) && (pRTE->i_uid <= U32_MAX ) ) ) return -EINVAL;

	//  i_uid can be any value whether ANY_I_UID bit set or not (0 is valid UID)
	

	// check 11

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
	 * note: these are not exclusive bitfield values:
	 *         we need to use "==" later in find_match()
	 *
	 *  from UserSpace, we expect setting .i_imode to one of S_***** constants
	 *  and setting ANY_I_MODE as necessary
	 **************************************************************************/

	if( pRTE->bitfield & ANY_I_MODE ) 
	{
		pRTE->i_mode = 0;
	}
	else
	{
		if( ! (pRTE->i_mode & S_IFMT) ) return -EINVAL;		// S_IFMT bits at all ?

		if(   (pRTE->i_mode & (~S_IFMT)) ) return -EINVAL;	// don't accept outside bits

	
		switch( pRTE->i_mode )
		{
			case S_IFSOCK:	break;

			case S_IFLNK:	break;

			case S_IFREG:	break;

			case S_IFBLK:	break;

			case S_IFDIR:	break;

			case S_IFCHR:	break;

			case S_IFIFO:	break;

			default:	return -EINVAL;
		}
	}



	// check 11a
	
	pRTE->which_hook = 0;		// reset to 0



	// check 11b
	
	pRTE->d_iname_len = 0;		// reset to 0



	// check 12

	if( pRTE->bitfield & ANY_D_INAME )
	{
		pRTE->d_iname[0] = 0;
	}
	else
	{
		pRTE->d_iname[SECCTL_DNAME_INLINE_LEN - 1] = 0;
		
		err = sanity_check_diname( pRTE->d_iname, SECCTL_DNAME_INLINE_LEN, 0x0 );
	
		if( err ) return -EINVAL;
	}


	// check 13

	pRTE->account = 0;		// reset to 0

	return 0;
}



// sanitize diname[] before printing via printk("%s", d_iname )
//
// when we receive a logged RTE packet from kernel,
// then we have a .d_iname[] which clearly should be 
// sanitized by the kernel already - but can we depend on it ?
// In particular, if diname would contain format specifiers like '%' !?
// So we better do a very strict sanitize for ourselves.
//
// Here we actually do substitute invalid chars by '.'
//
// arg #diname_buf_len is length of buffer, not length of diname
//

void sanitize_diname( char *diname, int diname_buf_len )
{
	(void) sanity_check_diname( diname, diname_buf_len, '.' );
}


static int sanity_validate_size_of_RTE(void)
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
		printk("secctl: init() ERROR: sizeof(RTE) != %u\n", RULE_TABLE_ENTRY_EXPECTED_SIZE );
		return -1;
	}

	return 0;
}


/* local helper function: get EUID of the running process
 * 
 * since current_euid() does return (kuid_t), we use this local 
 * helper function, also (hopefully) respecting namespaces;
 *
 *  see include/linux/uidgid.h for definition of from_kuid()
 *      depending on namespaces (enabled or not)
 *
 *  and kernel/user.c: struct user_namespace init_user_ns = {...}
 *  this struct seems to exist always, so we don't
 *  check "&init_user_ns" for validity
 */

static u32 local_get_euid( kuid_t kuid )
{
	uid_t  euid;

	euid = from_kuid( &init_user_ns, kuid );
	
	return (u32)euid;	
}



#ifdef DEBUG_SIZE_TEST_ACTIVE

void secctl_print_sizeof(void)
{
	printk("secctl: sizeof(u8 ) = %d\n", (u32)sizeof(u8 ));
	printk("secctl: sizeof(u16) = %d\n", (u32)sizeof(u16));
	printk("secctl: sizeof(u32) = %d\n", (u32)sizeof(u32));
	printk("secctl: sizeof(u64) = %d\n", (u32)sizeof(u64));
	printk("secctl: sizeof(char) = %d\n", (u32)sizeof(char));
	printk("secctl: sizeof(short) = %d\n", (u32)sizeof(short));
	printk("secctl: sizeof(int) = %d\n", (u32)sizeof(int));
	printk("secctl: sizeof(long) = %d\n", (u32)sizeof(long));
	printk("secctl: sizeof(unsigned char) = %d\n", (u32)sizeof(unsigned char));
	printk("secctl: sizeof(unsigned short) = %d\n", (u32)sizeof(unsigned short));
	printk("secctl: sizeof(unsigned int) = %d\n", (u32)sizeof(unsigned int));
	printk("secctl: sizeof(unsigned long) = %d\n", (u32)sizeof(unsigned long));
	printk("secctl: sizeof(RTE) = %d\n", (u32)sizeof(RULE_TABLE_ENTRY));
	printk("secctl: sizeof(MTE) = %d\n", (u32)sizeof(MOUNT_TABLE_ENTRY));
	printk("secctl: DNAME_INLINE_LEN = %d\n", (u32)DNAME_INLINE_LEN );
	printk("secctl: SECTTL_DNAME_INLINE_LEN = %d\n", (u32)SECCTL_DNAME_INLINE_LEN );
	printk("secctl: sizeof(uid_t) = %d\n", (u32)sizeof(uid_t));
	printk("secctl: sizeof(umode_t) = %d\n", (u32)sizeof(umode_t));
	printk("secctl: sizeof(jiffies) = %d (%lu)\n", (int)sizeof(jiffies), (long unsigned int) jiffies );
	printk("secctl: sizeof(dev_t) = %d\n", (u32)sizeof(dev_t) );

}

#else

void secctl_print_sizeof(void)
{
	return;
}

#endif


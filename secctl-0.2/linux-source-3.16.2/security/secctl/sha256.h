 
/* Note: For SHA256, we include crypto/sha256_generic.c from Linux Kernel 3.16.2 here,
 * slightly modified since it needs a little adaption to extract it from the Kernel crypto API
 *
 * Our crypto wrapper functions for secctl are in the lower half of this source file
 */

/////////////////////////////////////////////////////////// from Linux Kernel 3.16.2 crypto/sha256_generic.c //////////////////////////////////////////////////////////

/* Note: Although there are several memset() to clear sensitive data, the compiler
 * 	could optimize these essentially void functions away! 
 */

#include <asm/byteorder.h>			// for __be32/64 .. this include file is available in UserSpace /usr/include/asm/byteorder.h


/* from #include <linux/byteorder/little_endian.h> */
/* it didn't work to just include this file, maybe due to missing constants */
/* Note: x86 is LITTLE_ENDIAN though, so these macros are kept in case someone
   brings this code to work on a real big endian cpu (Not yet tested) */
   

#define cpu_to_be64(x) ((__be64)__swab64((x)))
#define cpu_to_be32(x) ((__be32)__swab32((x)))


/* from Kernel 3.16: include/crypto/sha.h --- Common values for SHA algorithms --- START */

#define SHA256_DIGEST_SIZE      32
#define SHA256_BLOCK_SIZE       64

#define SHA256_H0	0x6a09e667UL
#define SHA256_H1	0xbb67ae85UL
#define SHA256_H2	0x3c6ef372UL
#define SHA256_H3	0xa54ff53aUL
#define SHA256_H4	0x510e527fUL
#define SHA256_H5	0x9b05688cUL
#define SHA256_H6	0x1f83d9abUL
#define SHA256_H7	0x5be0cd19UL

struct sha256_state {
	u64 count;
	u32 state[SHA256_DIGEST_SIZE / 4];
	u8 buf[SHA256_BLOCK_SIZE];
};

/* ------------------------------------------------------------------------------- END */


static inline u32 Ch(u32 x, u32 y, u32 z)
{
	return z ^ (x & (y ^ z));
}

static inline u32 Maj(u32 x, u32 y, u32 z)
{
	return (x & y) | (z & (x | y));
}

#define ror32(x,n)	(((x)>>(n)) | ((x)<<(32-(n))))		// definition of <ror32> from GnuPG 1.4.10; didn't find it in the kernel

#define e0(x)       (ror32(x, 2) ^ ror32(x,13) ^ ror32(x,22))
#define e1(x)       (ror32(x, 6) ^ ror32(x,11) ^ ror32(x,25))
#define s0(x)       (ror32(x, 7) ^ ror32(x,18) ^ (x >> 3))
#define s1(x)       (ror32(x,17) ^ ror32(x,19) ^ (x >> 10))

static inline void LOAD_OP(int I, u32 *W, const u8 *input)
{
	W[I] = __be32_to_cpu( ((__be32*)(input))[I] );
}

static inline void BLEND_OP(int I, u32 *W)
{
	W[I] = s1(W[I-2]) + W[I-7] + s0(W[I-15]) + W[I-16];
}

static void sha256_transform(u32 *state, const u8 *input)
{
	u32 a, b, c, d, e, f, g, h, t1, t2;
	u32 W[64];
	int i;

	/* load the input */
	for (i = 0; i < 16; i++)
		LOAD_OP(i, W, input);

	/* now blend */
	for (i = 16; i < 64; i++)
		BLEND_OP(i, W);

	/* load the state into our registers */
	a=state[0];  b=state[1];  c=state[2];  d=state[3];
	e=state[4];  f=state[5];  g=state[6];  h=state[7];

	/* now iterate */
	t1 = h + e1(e) + Ch(e,f,g) + 0x428a2f98 + W[ 0];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x71374491 + W[ 1];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xb5c0fbcf + W[ 2];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xe9b5dba5 + W[ 3];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x3956c25b + W[ 4];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x59f111f1 + W[ 5];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x923f82a4 + W[ 6];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xab1c5ed5 + W[ 7];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xd807aa98 + W[ 8];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x12835b01 + W[ 9];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x243185be + W[10];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x550c7dc3 + W[11];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x72be5d74 + W[12];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x80deb1fe + W[13];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x9bdc06a7 + W[14];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xc19bf174 + W[15];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xe49b69c1 + W[16];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xefbe4786 + W[17];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x0fc19dc6 + W[18];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x240ca1cc + W[19];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x2de92c6f + W[20];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x4a7484aa + W[21];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5cb0a9dc + W[22];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x76f988da + W[23];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x983e5152 + W[24];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xa831c66d + W[25];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xb00327c8 + W[26];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xbf597fc7 + W[27];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0xc6e00bf3 + W[28];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xd5a79147 + W[29];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x06ca6351 + W[30];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x14292967 + W[31];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x27b70a85 + W[32];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x2e1b2138 + W[33];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x4d2c6dfc + W[34];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x53380d13 + W[35];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x650a7354 + W[36];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x766a0abb + W[37];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x81c2c92e + W[38];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x92722c85 + W[39];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0xa2bfe8a1 + W[40];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xa81a664b + W[41];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xc24b8b70 + W[42];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xc76c51a3 + W[43];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0xd192e819 + W[44];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xd6990624 + W[45];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0xf40e3585 + W[46];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x106aa070 + W[47];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x19a4c116 + W[48];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x1e376c08 + W[49];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x2748774c + W[50];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x34b0bcb5 + W[51];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x391c0cb3 + W[52];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x4ed8aa4a + W[53];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5b9cca4f + W[54];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x682e6ff3 + W[55];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	t1 = h + e1(e) + Ch(e,f,g) + 0x748f82ee + W[56];
	t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x78a5636f + W[57];
	t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x84c87814 + W[58];
	t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x8cc70208 + W[59];
	t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x90befffa + W[60];
	t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xa4506ceb + W[61];
	t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0xbef9a3f7 + W[62];
	t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xc67178f2 + W[63];
	t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;

	/* clear any sensitive info... */
	a = b = c = d = e = f = g = h = t1 = t2 = 0;			// not resistant wrt compiler optimization ?
	memset(W, 0, 64 * sizeof(u32));					// not resistant wrt compiler optimization ?
}





static int sha256_init(struct sha256_state *sctx)
{
	sctx->state[0] = SHA256_H0;
	sctx->state[1] = SHA256_H1;
	sctx->state[2] = SHA256_H2;
	sctx->state[3] = SHA256_H3;
	sctx->state[4] = SHA256_H4;
	sctx->state[5] = SHA256_H5;
	sctx->state[6] = SHA256_H6;
	sctx->state[7] = SHA256_H7;
	sctx->count = 0;

	return 0;
}

/*
 * Note: we did substitute input param <struct shash_desc *desc>
 *	to direct sha256 context <struct sha256_state *sctx>
 *	in each of the following functions.
 */


static int crypto_sha256_update(struct sha256_state *sctx, const u8 *data,
			  unsigned int len)
{
	unsigned int partial, done;
	const u8 *src;

	partial = sctx->count & 0x3f;
	sctx->count += len;
	done = 0;
	src = data;

	if ((partial + len) > 63) {
		if (partial) {
			done = -partial;
			memcpy(sctx->buf + partial, data, done + 64);
			src = sctx->buf;
		}

		do {
			sha256_transform(sctx->state, src);
			done += 64;
			src = data + done;
		} while (done + 63 < len);

		partial = 0;
	}
	memcpy(sctx->buf + partial, src, len - done);			// not resistant wrt compiler optimization ?

	return 0;
}

static int sha256_final(struct sha256_state *sctx, u8 *out)
{
	__be32 *dst = (__be32 *)out;
	__be64 bits;
	unsigned int index, pad_len;
	int i;
	static const u8 padding[64] = { 0x80, };

	/* Save number of bits */
	bits = cpu_to_be64(sctx->count << 3);

	/* Pad out to 56 mod 64. */
	index = sctx->count & 0x3f;
	pad_len = (index < 56) ? (56 - index) : ((64+56) - index);
	crypto_sha256_update(sctx, padding, pad_len);

	/* Append length (before padding) */
	crypto_sha256_update(sctx, (const u8 *)&bits, sizeof(bits));

	/* Store state in digest */
	for (i = 0; i < 8; i++)
		dst[i] = cpu_to_be32(sctx->state[i]);

	/* Zeroize sensitive information. */
	memset(sctx, 0, sizeof(*sctx));					// not resistant wrt compiler optimization ?

	return 0;
}


	
/////////////////////////////////////////////////////////// end of Linux Kernel 3.16.2 crypto/sha256_generic.c //////////////////////////////////////////////////////////

/*
 * These are crypto wrapper functions for secctl, which are based on SHA256 from <sha256_generic.c> above
 *
 */

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <linux/sysctl.h>
 
 
static u8 *sha256( u8 *p, size_t len );

static u8 *sha256_password( u8 *pw, u32 len, int *dummy );
static u8 *sha256_process_password( u8 *pstr, u32 len, u32 sha256_loops );
static int sha256_loop( u8 *array64, u32 sha256_loops );

static int sha256_selftest(void);

static u8 *hmac_sha256_core( u8 *key, u32 keylen, u8 *msg, u32 msglen );
static u8 *hmac_sha256( u8 *key, u32 keylen, u8 *msg, u32 msglen );
static int hmac_sha256_core_selftest(void);


/* do enable 
 *	#define SHA256_DEBUG(x)	x
 * and
 *	#define SHA256_DEBUG_PRINT
 *
 * for sha256 debug printf
 */


// #define SHA256_DEBUG(x)	x
#define SHA256_DEBUG(x)	(void)0;


// #define SHA256_DEBUG_PRINT
#ifdef SHA256_DEBUG_PRINT
static void sha256_print( u8 *p, u32 len )
{
	u32 i;
	
	for(i=0; i<len; i++)
	{
		// Note: for printf we use format string "%02X"
		// to print leading 0 for one-digit values, like 0x6 -> "06"

		printf("%02X", (u8) p[i] );
		
		if( ! ((i+1) & 3) ) printf(" ");
	}

	printf("\n");
}

#endif



/* call all sha sub-functions in one function call,
   all based on <sha256_generic.c> */

static u8 *sha256( u8 *p, size_t len )
{
	struct sha256_state ctx;
	static u8 digest[32];
	

	sha256_init( &ctx );
	
	crypto_sha256_update( &ctx, p, len );
	
	sha256_final( &ctx, digest );
	
	return digest;
}






/* direct syscall to retrieve system value <boot_id>
 * (can be done by any unpriv. user)
 *
 * doing a direct syscall does avoid reading same value from filesystem:
 *   /proc/sys/kernel/random/boot_id
 *
 * Note: this is a runtime unique ID, which is valid as long as the system is alive;
 *	After next reboot, a different random bootid will be calculated by the kernel;
 *
 * We will use this bootid as a random salt for converting the <lock|unlock> password
 * to a real key, which is then transmitted to the Kernel LSM via /dev/secctl.
 *
 * see Discussion about random salt in next function 
 *	sha256_process_password()
 */


int _sysctl(struct __sysctl_args *args );

#define BOOTID_LEN	16


// rc:
//  either	0  : syscall failed, no bootid available
//
//  or		&bootid[16] with hopefully valid bootid
//		(we do a little statistics test for bootid being in usual limits)


static u8 *get_system_unique_random_bootid(void)
{
	/* integer vector describing /proc/sys/kernel/random/boot_id */
	/* for constants see include/linux/sysctl.h */
	int ivector[] = { CTL_KERN, KERN_RANDOM, RANDOM_BOOT_ID };

	struct __sysctl_args	args;
	size_t			bootid_len;
	u32			i,sum;


	static u8		bootid[BOOTID_LEN];
	
	memset( bootid, 0, BOOTID_LEN );

	memset(&args, 0, sizeof(struct __sysctl_args));
	args.name = ivector;
	args.nlen = sizeof(ivector)/sizeof(ivector[0]);
	args.oldval = bootid;
	args.oldlenp = &bootid_len;

	if (syscall(SYS__sysctl, &args) == -1)	return 0;

	if( bootid_len != BOOTID_LEN ) return 0;

	/* statistics test:
	 *
	 * [0..255] * BOOTID_LEN entries in bootid[] should give <sum> approx. (128 * BOOTID_LEN)
	 *
	 * given a very small sample size of only #BOOTID_LEN, we treat more than
	 * 50 % deviation of (128 * BOOTID_LEN) as "unusual", and return 0 then
	 *
	 * 50 % deviation of (128 * BOOTID_LEN) is (64 * BOOTID_LEN)
	 *
	 * lower limit = (128 * BOOTID_LEN) - (64 * BOOTID_LEN) == (64 * BOOTID_LEN)
	 *
	 * upper limit = (128 * BOOTID_LEN) + (64 * BOOTID_LEN) == (192 * BOOTID_LEN)
	 */
	
	sum = 0;
	
	for(i=0; i<BOOTID_LEN; i++)
	{
		sum += (u32) bootid[i];
	}

// #define DEBUG_BOOTID
#ifdef DEBUG_BOOTID
	printf("bootID: ");
	for(i=0; i<BOOTID_LEN; i++)
	{
		printf("%02X ", (u8)bootid[i] );
	}
	printf("[sum: %u][expected: ~%u]\n", sum, 128 * BOOTID_LEN );
#endif


	if( !sum ) return 0;	// then all bootid[i] were zero !?

	 
	if( sum < (64 * BOOTID_LEN) ) return 0;
	if( sum > (192 * BOOTID_LEN) ) return 0;

	return (u8*) bootid;
	
}






/*
 * for SHA256_BASE_LOOPS: (you need not change this, but if you do:)
 *
 * please use a multiple of 8 since this simplifies our sanity check 
 * on statistics distribution quality of sha256 results.
 * In extremely rare cases, if statistics is not sufficient, 
 * a warning will be printed. Just use another password then.
 *
 * SHA256_BASE_LOOPS will be used as an outer factor for doing sha256 loops;
 * It will be multiplied with SHA256_LOOP_FACTOR to get the final number
 * of sha256 loops;
 */

#define SHA256_BASE_LOOPS	2000


#if SHA256_BASE_LOOPS % 8 != 0
# error "SHA256_BASE_LOOPS shall be a multiple of 8 !"
#endif
#if SHA256_BASE_LOOPS < 100
# error "SHA256_BASE_LOOPS shall be >= 100 !"
#endif
#if SHA256_BASE_LOOPS > 10000
# error "SHA256_BASE_LOOPS shall be <= 10000 !"
#endif


//
// convert pw[] thru sha256/hmac to digest
//
// rc:
//  either	(u8*) digest:  pointing to local_digest64[]
//
//  or		0  : error

static u8 *sha256_password( u8 *pw, u32 len, int *dummy )
{

	u32	SHA256_LOOP_FACTOR;
	static  u8 local_digest64[ 64 ];

	u8	*pdigest64;


	// 0 is only returned if statistical quality is not sufficient
	// (an error message was printed then by sha256_process_password())


	// smallest...biggest possible value for SHA256_LOOP_FACTOR:
	//
	// 	'0' == 0x30 == 48d
	//  		...
	//	'z' == 0x7a == 122d

	SHA256_LOOP_FACTOR = (u32) pw[0];


	// SHA256_BASE_LOOPS * SHA256_LOOP_FACTOR:
	//
	// 2000 * 48 = 96000 min. value
	// 2000 * 122 = 244000 max. value


	pdigest64 = sha256_process_password( (u8*)pw, len, SHA256_BASE_LOOPS * SHA256_LOOP_FACTOR );

	if( !pdigest64 ) return 0;


	memcpy( local_digest64, pdigest64, 64 );


	/****************************************************************************************
	 * sanitize sensitive data 
	 *
	 * Although lifetime of this program is very short, we should clear 
	 *	all the crypto arrays from sha256/hmac
	 *	(we note that memset(,0,) in Kernel 3.16.2 crypto/sha256_generic.c
	 *	was probably not safe to _not_ being optimized away by the compiler;
	 *	we use this source code in our sha256.h)
	 *
	 * we simply invoke sha256_process_password() again with a "dummy password";
	 *
	 * we need to convince the compiler to leave this calculation
	 * for _runtime_ of this program (e.g. not to pre-compute the result at compile-time)
	 *
	 * That's why we use the first 4 bytes from digest64[]
	 *   (which is not part of the 40 bytes digest in RTE.d_iname[])
	 */

	pdigest64 = sha256_process_password( (u8*)pdigest64, (u32)4, 8 );

	/* if( !pdigest64 ) return 0;  ... statistics issues do not count now */

	/* 
	 * now we need to convince the compiler to actually do sha256_process_password() at all
	 * by _using_ the result: we just copy the first byte of the result to our dummy rc
	 */

	if( pdigest64 )
		*dummy = (u32) pdigest64[0];
	else
		*dummy = 0;

	/****** sanitize end ********************************************************************/



	return local_digest64;
}




/*
 * Entropy Issue: Where from do we get random salt:
 *
 * We certainly should add real random salt for hmac, but this would need to be
 * persistently available across subsequent invocations of this program.
 * <lock> is one invocation, and <unlock> is the next invocation.
 *
 * So this salt would need to be stored somewhere, such that a later
 * invocation of this program could read it. But storing such a value
 * somewhere is contrary to the transient nature of this program.
 *
 * Or it could be a fixed random system variable which must not change over time,
 * and need to be accessible in a simple way, like </proc/sys/kernel/random/boot_id>
 * Unfortunately, usage of sysctl() to retrieve this value via syscall is discouraged
 * in the manpage(2). So we should have to read it from under /proc,
 * but this would really need another read() call with all the necessary safety
 * precautions.
 *
 *	For the time being, we use that discouraged "syscall(SYS__sysctl,"
 *	to retrieve bootid[16] directly;
 *
 * Another option would be a CPU serial number. But this is an issue for itself,
 * as not any CPU seems to have it. A Motherboard serial number seems to be 
 * accessible for root from /dev/mem (dmidecode). But relying on /dev/mem would really be
 * bad practice for a tool like this.
 *
 * Yet another option would be to use uname() or sysinfo(). But these do not provide
 * any kind of random system variables.
 *
 * Summary:
 *
 *  if we get bootid[16] via get_system_unique_random_bootid(), then we use it as pSALT_1
 *
 *  if we do not get bootid[16] via syscall, then we set pSALT_1 to our fixed SHA256_HMAC_SALT_1
 *
 *  SHA256_HMAC_SALT_2 is always used for further processing.
 */

#define SHA256_HMAC_SALT_1	"This is a non-secret sequence you might change anytime"
#define SHA256_HMAC_SALT_2	"And this is another not so random sequence you might change as well"

/* Note:
 *  the only disadvantage when changing SHA256_HMAC_SALT_1/2 is that you cannot <lock> the kernel,
 *  and then invoke another compiled <secctl> tool with another constant to <unlock> the kernel.
 *  These constants need to be equal for locking/unlocking (if bootid is available, then this
 *  applies only to _SALT_2)
 */

/* Note:
 *	<add reasoning here why we don't use Password Based Key Derivation Function PBKDF>
 *
 */
 
// Note: pw is not zero terminated!
//
// rc:
//  either	(u8*) double_digest:  pointing to 64 bytes digest
//
//  or		0  : error

static u8 *sha256_process_password( u8 *pw, u32 pw_len, u32 sha256_loops )
{	
	int	err;	
	u8	*psha256;
	static  u8 double_digest[64];
	u8	*pSALT_1;
	u32	pSALT_1_len;
	
		
	// test if sha256() and hmac() work as expected
	// (implementations can vary depending on LITTLE/BIG ENDIAN)
		
	err = sha256_selftest();	
	if( err ) 
	{
		fprintf(stderr,"ERROR: [lock|unlock] sha256 selftest not passed. Cannot proceed.\n");
		return 0;
	}
	err = hmac_sha256_core_selftest();	
	if( err ) 
	{
		fprintf(stderr,"ERROR: [lock|unlock] hmac selftest not passed. Cannot proceed.\n");
		return 0;
	}
	
	
	pSALT_1 = get_system_unique_random_bootid();

	if( pSALT_1 )
	{
		pSALT_1_len = BOOTID_LEN;
	}
	else
	{
		pSALT_1 = (u8*)SHA256_HMAC_SALT_1;
		pSALT_1_len = (u32)strlen(SHA256_HMAC_SALT_1);
	}

	//  SHA256_DEBUG( printf("pSALT_1: %s (%d)\n", pSALT_1, pSALT_1_len); )
	

	/* Now we call
	 *
	 *  hmac_sha256( pw[], pSALT_1 )	---> double_digest[]
	 *	|
	 *      -----------
	 *		  |
	 *		  v
	 *  hmac_sha256( sha256, SHA256_HMAC_SALT_2 )	---> &double_digest[32]
	 *
	 *
	 * Then we call our sha256_loop() function, which does 
	 *  iterate <sha256_loops> times over sha256() for each
	 * of the two 32-byte chunks of double_digest[]
	 */
		
	/* hmac_sha256() does always return a valid pointer to 32 byte array */
		
	psha256 = hmac_sha256( pw, pw_len, pSALT_1, pSALT_1_len );
		
	memcpy( double_digest, psha256, 32 );		SHA256_DEBUG( printf("hmac1:"); sha256_print( double_digest, 32 ); )

		
	psha256 = hmac_sha256( double_digest, 32, (u8*)SHA256_HMAC_SALT_2, (u32)strlen(SHA256_HMAC_SALT_2) );
		
	memcpy( &double_digest[32], psha256, 32 );	SHA256_DEBUG( printf("hmac2:"); sha256_print( &double_digest[32], 32 ); )
		


	err = sha256_loop( double_digest, sha256_loops );	// <---- our main sha256 loop

	if( err )
	{
		fprintf(stderr,"ERROR: <passwd> : statistical quality not sufficient; please use another password !\n");
		return 0;
	}

	SHA256_DEBUG( printf("sha256_process_password() final digest[64]:\n"); )
	SHA256_DEBUG( sha256_print( (u8*)double_digest, 32 ); )
	SHA256_DEBUG( sha256_print( (u8*)&double_digest[32], 32 ); )
	
	
	return double_digest;
}
		 


/*
 *  The following function sha256_loop() does send the
 *  	upper part of array64[] repeatedly thru sha256
 *  and send the
 *	lower part of array64[] repeatedly thru sha256
 *
 *  Number of repetitions is defined by #loops 
 */

// rc:
//  either	0  : OK
//
//  or		-1 : statistical quality not acceptable 
//		(this should normally not happen with SHA256, we test though)
//

static int sha256_loop( u8 *array64, u32 sha256_loops )
{
	u32	i;
	u8	*psha256;
	u32	distribution_1[256];
	u32	distribution_2[256];
	u32	k;
	u32	expectation;
	u32	deviation_1;
	u32	deviation_2;
	u32	sum_1;
	u32	sum_2;
	float	ssquare_1;
	float	ssquare_2;
	int 	err;
	

	memset( distribution_1, 0, 256 * sizeof(u32) );
	memset( distribution_2, 0, 256 * sizeof(u32) );

	for( i=0; i < sha256_loops; i++ )
	{
		/* sha256() does always return a valid pointer to 32 byte array */

		psha256 = sha256( array64, 32 );

		memcpy( array64, psha256, 32 );		// SHA256_DEBUG( printf("a:"); sha256_print( array64, 32 ); )

		for(k=0; k<32; k++)
		{
			distribution_1[ array64[k] ]++;
		}			

		psha256 = sha256( &array64[32], 32 );

		memcpy( &array64[32], psha256, 32 );	// SHA256_DEBUG( printf("b:"); sha256_print( &array64[32], 32 ); )

		for(k=0; k<32; k++)
		{
			distribution_2[ array64[k+32] ]++;
		}			

	}

	// done with computation of sha256 loops.
	
	
	// we do some internal statistics:
	// 1 byte can be 256 possible values,
	// each single sha256 does produce 32 bytes, statistically distributed;
	// 256 / 32 = 8
	// so after 8 single calls to sha256
	//	each of the possible 256 values should be produced approx. one time;
	// For <sha256_loops> loops, 
	//	each of the possible 256 values should be produced approx. #expectation times;

	expectation = sha256_loops >> 3;	// that's why we better define this const a multiple of 8

	if( expectation == 0 ) return -1;	// then <sha256_loops> was less than 8 (normally excluded by pre-compiler, see #if statements in secctl.c )

	sum_1 = 0;
	sum_2 = 0;

	for( k=0; k<256; k++ )
	{
		// we prefer to do any calculation here with u32;
		// abs() or labs() will not work with u32 as input param (according to manpage);
		// So we don't use abs() or labs(); and check ">" first to avoid negativ difference
		
		deviation_1 = distribution_1[k] > expectation ? distribution_1[k] - expectation :  expectation - distribution_1[k];
		
		sum_1 += deviation_1 * deviation_1;

		// SHA256_DEBUG( printf("1:\t%u\t%u\t%u\t\t\t", distribution_1[k], expectation, deviation_1 ); )

		deviation_2 = distribution_2[k] > expectation ? distribution_2[k] - expectation :  expectation - distribution_2[k];
		
		sum_2 += deviation_2 * deviation_2;

		// SHA256_DEBUG( printf("2:\t%u\t%u\t%u\n", distribution_2[k], expectation, deviation_2 ); )
	}

	ssquare_1 = (float)sum_1/(float)expectation;
	ssquare_2 = (float)sum_2/(float)expectation;

	SHA256_DEBUG( printf("sha256(password) statistics for %u sha256 loops --> each byte should be produced nearly expectation==%u times :\n", sha256_loops, expectation ); )
	SHA256_DEBUG( printf("SUM_1[ expectation - distribution_1[k] ]^2 : %u\t\tssquare : %f (256%+f)\n", sum_1, ssquare_1, ssquare_1 - 256.0); )
	SHA256_DEBUG( printf("SUM_2[ expectation - distribution_2[k] ]^2 : %u\t\tssquare : %f (256%+f)\n", sum_2, ssquare_2, ssquare_2 - 256.0); )


	// do a first-level check on distribution quality:
	
#define SHA256_TOL	76.8

	// 76.8 is 30% from 256.0 
	//
	//  ### This should really be only rarely be true. ####

	// if( fabs( ssquare_1 - 256.0 ) > SHA256_TOL ) return -1;
	// if( fabs( ssquare_2 - 256.0 ) > SHA256_TOL ) return -1;	would need linking -lm then for fabs()
	
	if( ssquare_1 > 256.0 )
	{
		if( (ssquare_1 - 256.0) > SHA256_TOL ) return -1;
	}
	else
	{
		if( (256.0 - ssquare_1) > SHA256_TOL ) return -1;
	}

	if( ssquare_2 > 256.0 )
	{
		if( (ssquare_2 - 256.0) > SHA256_TOL ) return -1;
	}
	else
	{
		if( (256.0 - ssquare_2) > SHA256_TOL ) return -1;
	}
	
	
	
	
	///////////////////////////////////////////////////////////////////////////////////	
	// Finally:
	// test those 40 bytes in the middle of array64[] for multiple times one byte.
	// We start at pos. k=12 in array64[]; from that position our password will be 
	// transfered to KernelSpace (later by calling function)

	memset( distribution_1, 0, 256 * sizeof(u32) );
	
	k = 12;
	
	for( i=0; i<40; i++ )
	{
		distribution_1[ array64[ k++ ] ]++;
	}
	
	
	err = 0;
	
	// if one byte is present more than SHA256_N_TIMES_ONE_BYTE times, we treat this as not acceptable
	// (be careful not to limit keyspace too much by setting this const too low)
	//
	//  ### This should really be only rarely be true. ####
	
#define SHA256_N_TIMES_ONE_BYTE		5

	for( i=0; i<256; i++ )
	{
		if( distribution_1[ i ] > SHA256_N_TIMES_ONE_BYTE ) { err = -1; break; }
	}

	if(err)
	{
		SHA256_DEBUG( printf("sha256: byte 0x%02X is present more than 5 times:\n", i ); )
		SHA256_DEBUG( sha256_print( &array64[12], 32 ); )
	}
	
	return err;
}
		

//
// rc:	0 : OK
//
//	-1: selftest NOT passed

static int sha256_selftest(void)
{
		/* example from GnuPG */
	char	*msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	u8	*psha256;
	u32	i;
				/* these are 32 bytes expected from sha256(msg) */
	u8 	digest[] = {	0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8,
				0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
				0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67,
				0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1 };
				
	// can be verified with
	// > echo -n "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" | sha256sum
	// 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
	//  (Linux/Knoppix 7.4)
	
	psha256 = sha256( (u8*)msg, strlen(msg) );

	for(i=0; i<32; i++ )
	{
		// printf("0x%02X <--> 0x%02X\n", digest[i], *psha256 );
		
		if( digest[i] != *(psha256++) ) return -1;
	}
	
	return 0;
}



// hmac-sha256 core
//
// Note:
//
// keylen and msglen need to be <= 64 !
//
// (this simplifies buffer handling: we can use
// longer than usual ipad[] and opad[] arrays directly 
// for string-concatenation (simply adding at &iopad[64])
//
// This function is only called from
//	hmac_sha256_core() and
//	hmac_sha256_core_selftest()
// which does ensure that keylen==msglen==32
//  (we could even shorten ipad/opad[64+64] to ipad/opad[64+32] then)
//
// rc:
//	ptr to 32 bytes of SHA256

static u8 *hmac_sha256_core( u8 *key, u32 keylen, u8 *msg, u32 msglen )
{
	u8	ipad[64+64];
	u8	opad[64+64];
	u8	*psha256;
	u32	i;

	if(keylen>64) keylen=64;	// we do a bounds checking anyway
	if(msglen>64) msglen=64;	// (this is not be true currently)
	
	memset( ipad, 0, 64+64 );
	memset( opad, 0, 64+64 );
	
	memcpy( ipad, key, keylen );
	memcpy( opad, key, keylen );
	
	for(i=0; i<64; i++ )
	{
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5C;
	}
	
	memcpy( &ipad[64], msg, msglen );
	
	psha256 = sha256( ipad, 64 + msglen );
	
	memcpy( &opad[64], psha256, 32 );
	
	psha256 = sha256( opad, 64 + 32 );
	
	return psha256;
}


// modified version of hmac-sha256
//
// instead of copying *key and *msg directly into ipad and opad,
// we send those input strings always(!) through sha256 first.
// So both input param <keylen> and <msglen> can be more easily > 64
// for calling hmac_sha256()
//
// rc:
//	ptr to 32 bytes of SHA256 (static u8 digest[32] in function sha256)

static u8 *hmac_sha256( u8 *key, u32 keylen, u8 *msg, u32 msglen )
{
	u8	sha256key[32];
	u8	sha256msg[32];
	u8*	psha256;
	
	psha256 = sha256( key, keylen );
	
	memcpy( sha256key, psha256, 32 );

	psha256 = sha256( msg, msglen );
	
	memcpy( sha256msg, psha256, 32 );


	/* Note: strlen(sha256key) and strlen(sha256msg) are now
	 *	== 32, which is <= 64 necessary
	 * when calling hmac_sha256_core() !
	 */
	
	return( hmac_sha256_core( sha256key, 32, sha256msg, 32) );
}



//
// rc:	0 : OK
//
//	-1: selftest NOT passed

static int hmac_sha256_core_selftest(void)
{
	char	*p1 = "key";	/* example from wikipedia.org */
	char	*p2 = "The quick brown fox jumps over the lazy dog";
	u8	*psha256;
	int	i;
	u8	digest[] = { 	0xF7, 0xBC, 0x83, 0xF4, 0x30, 0x53, 0x84, 0x24 ,
				0xB1, 0x32, 0x98, 0xE6, 0xAA, 0x6F, 0xB1, 0x43 ,
				0xEF, 0x4D, 0x59, 0xA1, 0x49, 0x46, 0x17, 0x59 ,
				0x97, 0x47, 0x9D, 0xBC, 0x2D, 0x1A, 0x3C, 0xD8 };


	/* Note: strlen(p1) and strlen(p2) need to be
	 *		<= 64
	 * when calling hmac_sha256_core() !
	 */

	psha256 = hmac_sha256_core( (u8*) p1, (u32) strlen(p1), (u8*) p2, (u32) strlen(p2) );


	/* for comparison, use /usr/bin/hmac256 (Linux/Knoppix 7.4)
	 *
	 * >echo -n "The quick brown fox jumps over the lazy dog" > /tmp/1 && /usr/bin/hmac256 key /tmp/1
	 *
	 * f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8  /tmp/1
	 *
	 */
	 
 	for(i=0; i<32; i++ )
	{
		// printf("0x%02X <--> 0x%02X\n", digest[i], *psha256 );
		
		if( digest[i] != *(psha256++) ) return -1;
	}

	return 0;
}

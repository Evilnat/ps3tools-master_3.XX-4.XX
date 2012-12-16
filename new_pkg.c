// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
//
// Added support for SPKGs files
// Modified by Evilnat

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <zlib.h>

static struct key k, z;
static FILE *fp, *fp2;

static u8 info0[0x40];
static u8 info1[0x40];

static u8 *content;
static u64 content_size_real;
static u64 content_size_compressed;

static u8 sce_hdr[0x20];
static u8 meta_hdr[0x260];

static u8 *pkg, *spkg;
static u64 pkg_size;

static void get_file(u8 *bfr, const char *name, u64 size)
{
	FILE *fp;

	fp = fopen(name, "rb");
	if (fp == NULL)
		fail("fopen(%s) failed", name);

	fread(bfr, size, 1, fp);
	fclose(fp);
}

static void get_content(void)
{
	u8 *base;
	uLongf size_zlib;
	int res;
	struct stat st;

	base = mmap_file("content");

	if (stat("content", &st) < 0)
		fail("stat(content) failed");

	content_size_real = st.st_size;
	content_size_compressed = compressBound(content_size_real);
	size_zlib = content_size_compressed;

	content = malloc(content_size_compressed);
	if (!content)
		fail("out of memory");

	res = compress(content, &size_zlib, base, content_size_real);
	if (res != Z_OK)
		fail("compress returned %d", res);

	content_size_compressed = size_zlib;
	content = realloc(content, content_size_compressed);
	if (!content)
		fail("out of memory");
}

static void get_key(const char *suffix)
{
	if (key_get(KEY_PKG, suffix, &k) < 0)
		fail("key_get() failed");

	if (k.pub_avail < 0)
		fail("no public key available");

	if (k.priv_avail < 0)
		fail("no private key available");

	if (ecdsa_set_curve(k.ctype) < 0)
		fail("ecdsa_set_curve failed");

	ecdsa_set_pub(k.pub);
	ecdsa_set_priv(k.priv);
}

static void get_key_spkg(void)
{
	if (key_get(KEY_SPKG, "retail", &z) < 0)
		fail("key_get() failed");

	if (z.pub_avail < 0)
		fail("no public key available");

	if (z.priv_avail < 0)
		fail("no private key available");

	if (ecdsa_set_curve(z.ctype) < 0)
		fail("ecdsa_set_curve failed");

	ecdsa_set_pub(z.pub);
	ecdsa_set_priv(z.priv);
}

static void build_sce_hdr(void)
{
	memset(sce_hdr, 0, sizeof sce_hdr);

	wbe32(sce_hdr + 0x00, 0x53434500);	// magic
	wbe32(sce_hdr + 0x04, 2);		// version
	wbe16(sce_hdr + 0x08, 0);		// dunno, sdk type?
	wbe16(sce_hdr + 0x0a, 3);		// SCE header type; pkg
	wbe32(sce_hdr + 0x0c, 0);		// meta offset
	wbe64(sce_hdr + 0x10, sizeof sce_hdr + sizeof meta_hdr);
	wbe64(sce_hdr + 0x18, 0x80 + content_size_real);
}

static void build_meta_hdr(void)
{
	u8 *ptr;

	memset(meta_hdr, 0, sizeof meta_hdr);
	ptr = meta_hdr;

	// keys for metadata encryptiomn
	get_rand(ptr, 0x10);
	get_rand(ptr + 0x20, 0x10);
	ptr += 0x40;

	// area covered by the signature
	wbe64(ptr + 0x00, sizeof sce_hdr + sizeof meta_hdr - 0x30);
	wbe16(ptr + 0x0a, 1);
	wbe32(ptr + 0x0c, 3);		// number of encrypted headers
	wbe32(ptr + 0x10, 4 * 5);	// number of keys/hashes required ++++++
	ptr += 0x20;

	// first info header
	wbe64(ptr + 0x00, 0x280);	// offset
	wbe64(ptr + 0x08, 0x40);	// size
	wbe32(ptr + 0x10, 1); 		// unknown
	wbe32(ptr + 0x14, 1);		// index
	wbe32(ptr + 0x18, 2);		// unknown again
	wbe32(ptr + 0x1c, 0);		// sha index
	wbe32(ptr + 0x20, 1);		// no encryption
	wbe32(ptr + 0x24, 0xffffffff);	// key index
	wbe32(ptr + 0x28, 0xffffffff);	// iv index
	wbe32(ptr + 0x2c, 0x1);		// no compression
	ptr += 0x30;

	// second info header
	wbe64(ptr + 0x00, 0x2c0);	// offset
	wbe64(ptr + 0x08, 0x40);	// size
	wbe32(ptr + 0x10, 2); 		// unknown
	wbe32(ptr + 0x14, 2);		// index
	wbe32(ptr + 0x18, 2);		// unknown again
	wbe32(ptr + 0x1c, 6);		// sha index
	wbe32(ptr + 0x20, 1);		// no encryption
	wbe32(ptr + 0x24, 0xffffffff);	// key index
	wbe32(ptr + 0x28, 0xffffffff);	// iv index
	wbe32(ptr + 0x2c, 0x1);		// no compression
	ptr += 0x30;

	// package files
	wbe64(ptr + 0x00, 0x300);	// offset
	wbe64(ptr + 0x08, content_size_compressed);
	wbe32(ptr + 0x10, 3); 		// unknown
	wbe32(ptr + 0x14, 3);		// index
	wbe32(ptr + 0x18, 2);		// unknown again
	wbe32(ptr + 0x1c, 12);		// sha index
	wbe32(ptr + 0x20, 3);		// encrypted
	wbe32(ptr + 0x24, 18);		// key index
	wbe32(ptr + 0x28, 19);		// iv index
	wbe32(ptr + 0x2c, 2);		// compressed
	ptr += 0x30;

	// add keys/ivs and hmac keys
	get_rand(ptr, 0x13c);
}

static void fix_info_hdr(void)
{
	wbe64(info0 + 0x18, content_size_real);
	wbe64(info0 + 0x20, content_size_compressed);
	wbe64(info1 + 0x18, content_size_real);
	wbe64(info1 + 0x20, 0x01);
}

static void build_pkg(void)
{
	pkg_size = sizeof sce_hdr + sizeof meta_hdr + 0x80;
	pkg_size += content_size_compressed;

	pkg = malloc(pkg_size);
	spkg = malloc(pkg_size);
	if (!pkg)
		fail("out of memory");

	memset(pkg, 0xaa, pkg_size);
	memcpy(pkg, sce_hdr, 0x20);
	memcpy(pkg + 0x20, meta_hdr, 0x260);
	memcpy(pkg + 0x280, info0, 0x40);	
	memcpy(pkg + 0x2c0, info1, 0x40);	
	memcpy(pkg + 0x300, content, content_size_compressed);
}

static void calculate_hash(u8 *data, u64 len, u8 *digest)
{
	memset(digest, 0, 0x20);
	sha1_hmac(digest + 0x20, data, len, digest);
}

static void hash_pkg(void)
{
	calculate_hash(pkg + 0x280, 0x40, pkg + 0x80 + 3*0x30);
	calculate_hash(pkg + 0x2c0, 0x40, pkg + 0x60 + 3*0x30 + 8*0x10);
	calculate_hash(pkg + 0x300, content_size_compressed, 
			pkg + 0x40 + 3*0x30 + 16*0x10);
}

static void sign_pkg(void)
{
	u8 *r, *s;
	u8 hash[20];
	u64 sig_len;

	sig_len = be64(pkg + 0x60);
	r = pkg + sig_len;
	s = r + 21;

	sha1(pkg, sig_len, hash);

	ecdsa_sign(hash, r, s);
}


int main(int argc, char *argv[])
{
	char spkg_file[100];
	sprintf(spkg_file, "%s.spkg_hdr.1", argv[3]);	

	if (argc != 4)
	{
		printf("\nnew_pkg.exe\nModified by Evilnat\n\nAdded SPKG support\nIt creates a valid spkg file for generated pkg\n\n");
		fail("usage: new_pkg [key suffix] [contents] [filename.pkg]\n");
	} 

	printf("\nnew_pkg.exe\nModified by Evilnat\n\n");
	printf("Please wait...\n\n");

	// open file for PKG
	fp = fopen(argv[3], "wb");
	if (fp == NULL)
		fail("fopen(%s) failed", argv[3]);

	// open file for SPKG
	fp2 = fopen(spkg_file, "wb");
	if (fp2 == NULL)
		fail("fopen(%s) failed", spkg_file);

	if (chdir(argv[2]) < 0)
	fail("chdir");	

	get_key(argv[1]);

	// File content
	get_file(info0, "info0", 0x40);
	get_file(info1, "info1", 0x40);
	get_content();

	build_sce_hdr(); // Header
	build_meta_hdr(); // Metaheader
	fix_info_hdr(); // Fix info

	build_pkg(); // Create PKG
	hash_pkg(); // Hash PKG
	sign_pkg(); // Sign PKG

	memcpy(spkg, pkg, pkg_size); // Copy buffer

	// data pkg	
	sce_encrypt_data(pkg);
	sce_encrypt_header(pkg, &k);
	fwrite(pkg, pkg_size, 1, fp);
	fclose(fp);	

	// data spkg
	get_key_spkg();
 	sce_encrypt_data(spkg);
	sce_encrypt_header(spkg, &z);
	fwrite(spkg, 0x280, 1, fp2);
	fclose(fp2);		

	printf("\nDone");

	return 0;
}

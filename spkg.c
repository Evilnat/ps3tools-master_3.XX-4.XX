// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
//
// Modified by Evilnat to create valid spkg files for CFW 4.XX

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <zlib.h>

static struct key z;
static FILE *fp2;
static u64 dec_size;
static u32 meta_offset;
static u32 n_sections;
static u8 *pkg;

static void get_key()
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

static void decrypt_pkg(void)
{
	u16 flags;
	u16 type;
	u32 hdr_len;
	struct keylist *k;

	flags    = be16(pkg + 0x08);
	type     = be16(pkg + 0x0a);
	hdr_len  = be64(pkg + 0x10);
	dec_size = be64(pkg + 0x18);

	if (type != 3)
		fail("no .spkg file");

	k = keys_get(KEY_PKG);

	if (k == NULL)
		fail("no key found");

	if (sce_decrypt_header(pkg, k) < 0)
		fail("header decryption failed");

	meta_offset = be32(pkg + 0x0c);
	n_sections  = be32(pkg + meta_offset + 0x60 + 0xc);

	if (n_sections != 3)
		fail("invalid section count: %d", n_sections);
}

int main(int argc, char *argv[])
{
	char decrypted[100];
	sprintf(decrypted, "%s.spkg_hdr.1", argv[1]);	

	if (argc != 2)
	{
		printf("\nspkg.exe\nCreated by Evilnat\n\n");
		fail("usage: spkg [filename.pkg]\n");
	} 

	printf("\nspkg.exe\nCreated by Evilnat\n\n");
	printf("\nPlease wait...\n\n");

	pkg = mmap_file(argv[1]);

	fp2 = fopen(decrypted, "wb");
	if (fp2 == NULL)
		fail("fopen(%s) failed", decrypted);

	decrypt_pkg();
	get_key();

	sce_encrypt_header(pkg, &z);
	fwrite(pkg, 0x280, 1, fp2);
	fclose(fp2);

	printf("\nDone");

	return 0;
}

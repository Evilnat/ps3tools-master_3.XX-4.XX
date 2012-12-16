// Copyright 2010       Sven Peter <svenpeter@gmail.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
//
// Exports spkg decrypted header/metadata
// Modified by Evilnat

#include "tools.h"
#include "types.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

static FILE *fp;
u8 *pkg = NULL;
static u64 dec_size;
static u32 meta_offset;
static u32 n_sections;
u32 hdr_len;

static void decrypt_spkg(void)
{
	u16 flags;
	u16 type;	
	struct keylist *k;

	flags    = be16(pkg + 0x08);
	type     = be16(pkg + 0x0a);
	hdr_len  = be64(pkg + 0x10);
	dec_size = be64(pkg + 0x18);

	if (type != 3)
		fail("no .spkg file");

	k = keys_get(KEY_SPKG);

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
	if (argc != 3)
	{
		printf("\nunspkg.exe\nCreated by Evilnat\n\nExports spkg decrypted header/metadata\n\n");
		fail("usage: unspkg filename.spkg output\n");
	}

	printf("\nunspkg.exe\nModified by Evilnat\n\n");
	printf("Please wait...\n\n");

	fp = fopen(argv[2], "wb");
	if (fp == NULL)
		fail("fopen(%s) failed", argv[2]);

	pkg = mmap_file(argv[1]);

	decrypt_spkg();
	fwrite(pkg, 0x280, 1, fp);

	printf("\nDone\n");

	return 0;
}

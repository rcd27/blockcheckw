#include "gzip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helpers.h"

#define ZCHUNK 16384
#define BUFMIN 128
#define BUFCHUNK (1024*128)

int z_readfile(FILE *F, char **buf, size_t *size, size_t extra_alloc)
{
	z_stream zs;
	int r;
	unsigned char in[ZCHUNK];
	size_t bufsize;
	void *newbuf;
	size_t rd;

	memset(&zs, 0, sizeof(zs));

	*buf = NULL;
	bufsize = *size = 0;

	r = inflateInit2(&zs, 47);
	if (r != Z_OK)  return r;

	do
	{
		if (!fread_safe(in, 1, sizeof(in), F, &rd))
		{
			r = Z_ERRNO;
			goto zerr;
		}
		if (!rd)
		{
			// file is not full
			r = Z_DATA_ERROR;
			goto zerr;
		}
		zs.avail_in = rd;
		zs.next_in = in;

		for(;;)
		{
			if ((bufsize - *size) < BUFMIN)
			{
				bufsize += BUFCHUNK;
				newbuf = *buf ? realloc(*buf, bufsize + extra_alloc) : malloc(bufsize + extra_alloc);
				if (!newbuf)
				{
					r = Z_MEM_ERROR;
					goto zerr;
				}
				*buf = newbuf;
			}
			zs.avail_out = bufsize - *size;
			zs.next_out = (unsigned char*)(*buf + *size);

			r = inflate(&zs, Z_NO_FLUSH);

			*size = bufsize - zs.avail_out;
			if (r==Z_STREAM_END) break;
			if (r==Z_BUF_ERROR)
			{
				if (zs.avail_in)
					goto zerr;
				else
				{
					r = Z_OK;
					break;
				}
			}
			if (r!=Z_OK) goto zerr;
		}
	} while (r == Z_OK);

	if (*size < bufsize)
	{
		if (*size + extra_alloc)
		{
			// free extra space
			if ((newbuf = realloc(*buf, *size + extra_alloc))) *buf = newbuf;
		}
		else
		{
			free(*buf);
			*buf = NULL;
		}
	}

	inflateEnd(&zs);
	return r;

zerr:
	inflateEnd(&zs);
	free(*buf);
	*buf = NULL;
	return r;
}

bool is_gzip(FILE* F)
{
	unsigned char magic[2];
	bool b = !fseek(F, 0, SEEK_SET) && fread(magic, 1, 2, F) == 2 && magic[0] == 0x1F && magic[1] == 0x8B;
	fseek(F, 0, SEEK_SET);
	return b;
}

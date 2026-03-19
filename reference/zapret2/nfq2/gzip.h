#pragma once

#include <stdio.h>
#include <zlib.h>
#include <stdbool.h>

int z_readfile(FILE *F, char **buf, size_t *size, size_t extra_alloc);
bool is_gzip(FILE* F);

#ifndef _DUMP_PRINT_H
#define _DUMP_PRINT_H
#include <stdio.h>

void dump_print(char* comment,int buf_len, void *buf);
void dump_fprintf(FILE*fp,char* comment,int buf_len, void *buf);

#endif


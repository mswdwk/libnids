#include "dump_print.h"

void dump_print(char* comment,int buf_len, void *buf)
{
    int i;
	if(!buf)return;
    if(comment)printf("\n%s length %d",comment, buf_len);
    for (i = 0; i < buf_len; i++) {
        if ((i & 0xf) == 0)
            printf( "\n0x%08X  ",i);
        printf( "%02X%s", (((unsigned char*)buf)[i]&0xff),(i+1)&0x3 ? "":" ");
    }
    printf( "\n\n");
}

void dump_fprintf(FILE*fp,char* comment,int buf_len, void *buf)
{
    int i;
	if(!buf || !fp)return;
    if(comment)fprintf(fp,"%s length %d",comment, buf_len);
    for (i = 0; i < buf_len; i++) {
        if ((i & 0xf) == 0)
            fprintf(fp, "\n0x%08X  ",i);
        fprintf(fp,"%02X%s", (((unsigned char*)buf)[i]&0xff),(i+1)&0x3 ? "":" ");
    }
    fprintf(fp, "\n\n");
}




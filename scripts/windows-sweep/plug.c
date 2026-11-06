/* A plugin: read the artifact from stdin, reply with one line of JSON. */
#include <stdio.h>
int main(void){ long n=0; int c; while((c=getchar())!=EOF) n++; printf("{\"plugin_saw_bytes\":%ld}\n", n); return 0; }

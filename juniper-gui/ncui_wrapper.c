/*
 * ncui wrapper, which reads parameters from command line and launching ncui.
 * This is done to avoid DSID visibility in process list

 * The author has placed this work in the Public Domain, thereby relinquishing
 * all copyrights. Everyone is free to use, modify, republish, sell or give away
 * this work without prior consent from anybody.

 * This software is provided on an "as is" basis, without warranty of any
 * kind. Use at your own risk! Under no circumstances shall the author(s) or
 * contributor(s) be liable for damages resulting directly or indirectly from
 * the use or non-use of this software.
*/

/* To build on 64 bit:
 *  gcc -m32 ncui_wrapper.c -ldl -o ncui_wrapper
*/

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE 1024
#define MAX_ARGS 20

int main(int argc, char** argv)
{
    void* handle;
    char* error;
    char** newargv;
    char buffer[BUF_SIZE];
    int newargc = 0, len;

    handle = dlopen("./libncui.so", RTLD_LAZY);
    if (!handle) 
    {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    dlerror(); /* Clear any existing error */

    /* pass our arguments to ncui library main function */
    int (*ncui)(int, char**) = dlsym(handle, "main");
    ncui(argc, argv);

    if ((error = dlerror()) != NULL) 
    {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }

    dlclose(handle);
    exit(EXIT_SUCCESS);
}

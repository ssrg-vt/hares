/*
 * Created on Fri Feb 14 2020
 *
 * Copyright (c) 2020 xxx xxx, xxxx
 */

#include "dnet_ocalls.h"

//#define DISABLE_CACHE //open files with O_DIRECT thus bypassing kernel page cache for reads and writes

//File pointers used for reading and writing files from within the enclave runtime
FILE *write_fp = NULL;
FILE *read_fp = NULL;
//file descriptor used by open
int fd;
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

/* Free section in untrusted memory*/
void ocall_free_sec(section *sec)
{
    //printf("Freeing section in ocall..\n");
    free_section(sec);
}

void ocall_free_list(list *list)
{
    free_list(list);
}

// 0 for read: 1 for write
void ocall_open_file(const char *filename, flag oflag)
{

    if (!write_fp && !read_fp) //fp == NULL
    {
        switch (oflag)
        {
        case O_RDONLY:
#ifdef DISABLE_CACHE
            fd = open(filename, O_RDONLY | O_CREAT | O_DIRECT);
            read_fp = fdopen(fd, "rb");

#else
            read_fp = fopen(filename, "rb");
#endif

            printf("Opened file in read only mode\n");
            break;
        case O_WRONLY:
#ifdef DISABLE_CACHE
            fd = open(filename, O_WRONLY | O_CREAT | O_DIRECT);
            write_fp = fdopen(fd, "wb");

#else
            write_fp = fopen(filename, "wb");
#endif

            printf("Opened file in write only mode\n");
            break;
        case O_RDPLUS:
#ifdef DISABLE_CACHE
//TODO
#endif
            read_fp = fopen(filename, "r+");
            break;
        case O_WRPLUS:
#ifdef DISABLE_CACHE
//TODO
#endif
            write_fp = fopen(filename, "w+");
            break;
        default:; //nothing to do
        }
    }
    else
    {
        printf("Problem with file pointer..\n");
    }
}

/**
 * Close all file descriptors
 */
void ocall_close_file()
{
#ifdef DISABLE_CACHE

#endif
    if (read_fp) //fp != NULL
    {
        fclose(read_fp);
        read_fp = NULL;
    }
    if (write_fp)
    {
        fclose(write_fp);
        write_fp = NULL;
    }
}

void ocall_fread(void *ptr, size_t size, size_t nmemb)
{
    if (read_fp)
    {
        fread(ptr, size, nmemb, read_fp);
    }
    else
    {
        printf("Corrupt file pointer..\n");
        abort();
    }
}

void ocall_fwrite(void *ptr, size_t size, size_t nmemb)
{
    int ret;
    if (write_fp)
    {
        fwrite(ptr, size, nmemb, write_fp);
        //make sure it is flushed to disk first
        ret = fflush(write_fp);
        if (ret != 0)
            printf("fflush did not work..\n");
        /*  ret = fsync(fileno(fp));
        if (ret < 0)
            printf("fsync did not work..\n"); */
        return;
    }
    else
    {
        printf("Corrupt file pointer..\n");
        abort();
    }
}
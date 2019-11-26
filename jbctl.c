/* Copyright (C) 2018-2019 Sam Bingner All rights reserved.
 */

#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/error.h>
#include <sys/queue.h>
#include <getopt.h>

#include <offsetcache.h>
#include "unc0ver.h"

bool initialized = false;
FILE *log_file = NULL;
uint64_t offset_options = 0;
uint64_t offset_cr_flags = 0;
uint64_t offset_zonemap=0;
uint64_t kernel_task_kaddr=0;
uint64_t kernel_task_offset_all_image_info_addr=0;
mach_port_t tfp0=0;

static unsigned debug=0;
extern const char ***_NSGetArgv(void);

enum operation {
    OP_UNDEFINED = 0,
    OP_SHOWALL,
};

enum mode {
    MODE_OFFSETS = 0,
    MODE_UNRESTRICT = 1,
};

static struct option long_options[] = {
	{"help",    no_argument,       0, 'h'},
	{"all",     no_argument,       0, 'a'},
	{"quiet",   no_argument,       0, 'q'},
	{0,         0,                 0,  0 }
};

void usage(void)
{
    printf("Usage: %s [OPTIONS...] [name=value]\n", (*_NSGetArgv())[0]);
    printf("\t-h, --help         Print this help\n");
    printf("\t-a, --all          Show all saved offsets\n");
    printf("\t-q, --quiet        Don't print names of offsets\n");
    if (offset_options) printf("\t-u, --unrestrict   Get/Set unrestrict settings instead of offsets\n");
}

size_t kernel_read(uint64_t addr, void *buf, size_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        return 0;
    }
    kern_return_t ret;
    vm_size_t remainder = size,
              bytes_read = 0;

    // The vm_* APIs are part of the mach_vm subsystem, which is a MIG thing
    // and therefore has a hard limit of 0x1000 bytes that it accepts. Due to
    // this, we have to do both reading and writing in chunks smaller than that.
    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > 0xfff ? 0xfff : remainder;
        ret = vm_read_overwrite(tfp0, addr, size, (vm_address_t)&((char*)buf)[bytes_read], &size);
        if(ret != KERN_SUCCESS || size == 0)
        {
            fprintf(stderr, "vm_read error: %s", mach_error_string(ret));
            break;
        }
        bytes_read += size;
        addr += size;
    }

    return bytes_read;
}

uint64_t rk64(uint64_t addr)
{
    uint64_t val = 0;
    kernel_read(addr, &val, sizeof(val));
    return kernel_read(addr, &val, sizeof(val))==sizeof(val)?val:0xdeadbeefdeadbeef;
}

size_t kernel_write(uint64_t addr, void *buf, size_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        return 0;
    }
    kern_return_t ret;
    vm_size_t remainder = size,
              bytes_written = 0;

    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > 0xfff ? 0xfff : remainder;
        ret = vm_write(tfp0, addr, (vm_offset_t)&((char*)buf)[bytes_written], size);
        if(ret != KERN_SUCCESS)
        {
            fprintf(stderr, "vm_write error: %s", mach_error_string(ret));
            break;
        }
        bytes_written += size;
        addr += size;
    }

    return bytes_written;
}

bool wk64(uint64_t addr, uint64_t val)
{
    return kernel_write(addr, &val, sizeof(val)) == sizeof(val);
}

uint64_t kmem_alloc(size_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        return 0;
    }

    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);

    err = mach_vm_allocate(tfp0, &addr, ksize, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "unable to allocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return 0;
    }
    return addr;

}

uint64_t kmem_alloc_wired(size_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        return 0;
    }

    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);

    err = mach_vm_allocate(tfp0, &addr, ksize, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "unable to allocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return 0;
    }

    host_t host = mach_host_self();
    err = mach_vm_wire(host, tfp0, addr, ksize, VM_PROT_READ | VM_PROT_WRITE);
    mach_port_deallocate(mach_task_self(), host);
    host = HOST_NULL;
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "unable to wire kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return 0;
    }

    return addr;
}

bool kmem_free(uint64_t kaddr, uint64_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        fprintf(stderr, "attempt to deallocate kernel memory before any kernel memory write primitives available");
        return false;
    }
    
    kern_return_t err;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_deallocate(tfp0, kaddr, ksize);
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "unable to deallocate kernel memory via tfp0: %s %x", mach_error_string(err), err);
        return false;
    }
    
    return true;
}

int main(int argc, char * const* argv) {
    int option_index = 0;
    enum operation op = OP_UNDEFINED;
    enum mode mode = MODE_OFFSETS;
    bool found_offsets = true;
    bool quiet = false;
    char c;
    kern_return_t err;

    // tfp0, kexecute
    err = task_for_pid(mach_task_self(), 0, &tfp0);
    if (err != KERN_SUCCESS) {
        err = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
        if (err != KERN_SUCCESS) {
            fprintf(stderr, "host_get_special_port 4: %s", mach_error_string(err));
            tfp0 = KERN_INVALID_TASK;
            return -1;
        }
    }

    struct {
        mach_vm_address_t       all_image_info_addr;
        mach_vm_size_t          all_image_info_size;
        integer_t               all_image_info_format;
        struct task_dyld_info pad[3];
    } dyld_info = {};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    int rv;
    if ((rv=task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count)) != 0 ||
            dyld_info.all_image_info_addr == 0 ||
            dyld_info.all_image_info_addr == dyld_info.all_image_info_size + 0xfffffff007004000) {
        fprintf(stderr, "task_info(tfp0) rv: %d; all_image_info_addr: %llx\nall_image_info_size: %llx\n", rv, dyld_info.all_image_info_addr, dyld_info.all_image_info_size);
        return -2;
    }
    uint64_t kernel_slide = dyld_info.all_image_info_size;
    size_t blob_size = rk64(dyld_info.all_image_info_addr);
    struct cache_blob *blob = create_cache_blob(blob_size);

    if (kernel_read(dyld_info.all_image_info_addr, blob, blob_size)) import_cache_blob(blob);
    free(blob);
    if (get_offset("kernel_slide") != kernel_slide) {
        found_offsets = false;
        fprintf(stderr, "WARNING: kernel_slide 0x%llx from offsets does not match actual slide of 0x%llx (no unrestrict options available)\n", get_offset("kernel_slide"), kernel_slide);
        offset_cr_flags = offset_options = 0;
        if (mode == MODE_UNRESTRICT) exit(-3);
    }
    offset_options = get_offset("unrestrict-options");
    offset_cr_flags = get_offset("checkrain-flags");
    if (!offset_cr_flags && !offset_options) {
        fprintf(stderr, "WARNING: Missing unrestrict-options, will not be able to use unrestrict options\n");
        if (mode == MODE_UNRESTRICT) exit(-3);
    }
    if (debug && offset_options) fprintf(stderr, "unrestrict-options at 0x%llx: 0x%llx\n", offset_options, rk64(offset_options));
    if (debug && offset_cr_flags) fprintf(stderr, "checkrain-flags at 0x%llx: 0x%llx\n", offset_cr_flags, rk64(offset_cr_flags));

    while ((c = getopt_long(argc, argv, "adhqu", long_options, &option_index)) != -1) {
        switch (c) {
            case 'a':
                if (op != OP_UNDEFINED) {
                    fprintf(stderr, "Error: multiple operations not supported\n");
                    usage();
                    exit(1);
                }
                op = OP_SHOWALL;
                break;
            case 'u':
                if (offset_options) {
                    mode = MODE_UNRESTRICT;
                } else {
                    usage();
                    exit(1);
                }
                break;
            case 'h':
                usage();
                exit(0);
                break;
            case 'q':
                quiet = true;
                break;
            case 'd':
                debug++;
                fprintf(stderr, "Debug level %d\n", debug);
                break;
            default:
                usage();
                exit(1);
                break;
        }
    }

    //offset_zonemap = get_offset("zonemap");
    uint64_t kernel_task = get_offset("kernel_task");
    if (kernel_task) {
        kernel_task_kaddr = rk64(kernel_task);
        kernel_task_offset_all_image_info_addr = get_offset("kernel_task_offset_all_image_info_addr");
        if (!kernel_task_offset_all_image_info_addr) {
            fprintf(stderr, "WARNING: Missing required kernel_task_offset_all_image_info_addr, will not be able to save changes\n");
            found_offsets = false;
        }
    } else {
        fprintf(stderr, "WARNING: Missing required kernel_task offset, will not be able to save changes\n");
        found_offsets = false;
    }

    bool offsets_changed = false;
    for (int i=optind; i<argc; i++) {
        op = OP_UNDEFINED; // Reset this so adding -a doesn't make it print things other than what was set
        char *name = argv[i];
        char *valuestr = strchr(argv[i], '=');
        if (valuestr) {
            *valuestr = '\0';
            valuestr++;
            if (mode == MODE_OFFSETS) {
                uint64_t value = strtoull(valuestr, NULL, 0);
                if (errno==EINVAL || errno==ERANGE) {
                    fprintf(stderr, "Unable to set %s: %s", name, strerror(errno));
                } else {
                    set_offset(name, value);
                    printf("%s=0x%llx\n", name, value);
                    offsets_changed = true;
                }
            } else if (mode == MODE_UNRESTRICT) {
                bool value;
                if (strcasecmp(valuestr, "yes")==0) {
                    value = true;
                } else if (strcasecmp(valuestr, "no")==0) {
                    value = false;
                } else {
                    usage();
                    exit(1);
                }
                if (strcmp(name, "GET_TASK_ALLOW")==0) {
                    SETOPT(GET_TASK_ALLOW, value);
                    printf("GET_TASK_ALLOW=%s\n", OPT(GET_TASK_ALLOW)?"yes":"no");
                } else if (strcmp(name, "CS_DEBUGGED")==0) {
                    SETOPT(CS_DEBUGGED, value);
                    printf("CS_DEBUGGED=%s\n", OPT(CS_DEBUGGED)?"yes":"no");
                } else {
                    usage();
                    exit(1);
                }
            }
        } else {
            if (mode == MODE_OFFSETS) {
                if (!quiet) printf("%s=", argv[i]);
                printf("0x%llx\n", get_offset(argv[i]));
            } else if (mode == MODE_UNRESTRICT) {
                if (strcmp(name, "GET_TASK_ALLOW")==0) {
                    printf("GET_TASK_ALLOW=%s\n", OPT(GET_TASK_ALLOW)?"yes":"no");
                } else if (strcmp(name, "CS_DEBUGGED")==0) {
                    printf("CS_DEBUGGED=%s\n", OPT(CS_DEBUGGED)?"yes":"no");
                }
            }
        }
    }

    if (offsets_changed) {
        if (!kernel_task_offset_all_image_info_addr || !kernel_task_kaddr) {
            fprintf(stderr, "Unable to update offsets in kernel due to missing: %s%s\n", kernel_task_offset_all_image_info_addr?"":"kernel_task_offset_all_image_info_addr ", kernel_task_kaddr?"":"kernel_task_kaddr");
            return -2;
        }
        uint64_t old_blob = dyld_info.all_image_info_addr;
        uint64_t old_blob_size = rk64(dyld_info.all_image_info_addr);

        struct cache_blob *cache;
        size_t cache_size = export_cache_blob(&cache);
        if (cache_size <= sizeof(struct cache_blob)) {
            fprintf(stderr, "Cache size makes no sense, aborting\n");
            if (cache_size > 0)
                free(cache);
            return(-1);
        }
        uint64_t kernel_cache_blob = kmem_alloc(cache_size);
        blob_rebase(cache, (uint64_t)cache, kernel_cache_blob);
        kernel_write(kernel_cache_blob, cache, cache_size);
        free(cache);
        wk64(kernel_task_kaddr + kernel_task_offset_all_image_info_addr, kernel_cache_blob);
        kmem_free(old_blob, old_blob_size);
    }

    switch (op) {
        case OP_SHOWALL:
            if (mode == MODE_OFFSETS) {
                blob_size = export_cache_blob(&blob);
                offset_entry_t *np;
                TAILQ_FOREACH(np, &blob->cache, entries) {
                    if (!quiet) printf("%s=", np->name);
                    printf("0x%llx\n", np->addr);
                }
                free(blob);
            } else if (mode == MODE_UNRESTRICT) {
                printf( "GET_TASK_ALLOW=%s\n"
                        "CS_DEBUGGED=%s\n",
                        OPT(GET_TASK_ALLOW)?"yes":"no",
                        OPT(CS_DEBUGGED)?"yes":"no");
            } else {
                usage();
                exit(2);
            }
            break;
        default:
            if (optind==argc) {
                usage();
                exit(1);
            }
            break;
    }

    return 0;
}

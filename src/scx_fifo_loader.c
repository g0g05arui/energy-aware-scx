// SPDX-License-Identifier: GPL-2.0
/* Userspace loader for FIFO sched_ext scheduler */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int keep_running = 1;

void sig_handler(int signo) {
    keep_running = 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_link *link = NULL;
    int err;
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Set up libbpf logging */
    libbpf_set_print(NULL);
    
    /* Load BPF object file */
    const char *bpf_obj_path = argc > 1 ? argv[1] : "scx_fifo.bpf.o";
    
    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: failed to open BPF object at %s: %s\n", 
                bpf_obj_path, strerror(errno));
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    /* Find and attach the scheduler struct_ops */
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *prog_name = bpf_program__name(prog);
        
        if (bpf_program__type(prog) == BPF_PROG_TYPE_STRUCT_OPS) {
            link = bpf_map__attach_struct_ops(
                bpf_object__find_map_by_name(obj, "fifo_ops")
            );
            if (libbpf_get_error(link)) {
                fprintf(stderr, "ERROR: failed to attach struct_ops: %s\n", 
                        strerror(errno));
                link = NULL;
                goto cleanup;
            }
            break;
        }
    }
    
    if (!link) {
        fprintf(stderr, "ERROR: no struct_ops program found\n");
        err = -1;
        goto cleanup;
    }
    
    printf("FIFO scheduler loaded and attached successfully\n");
    printf("Press Ctrl+C to stop and unload the scheduler\n\n");
    
    /* Wait for signal */
    while (keep_running) {
        sleep(1);
    }
    
    printf("\nUnloading scheduler...\n");
    
cleanup:
    if (link)
        bpf_link__destroy(link);
    if (obj)
        bpf_object__close(obj);
    
    printf("Scheduler unloaded\n");
    return err != 0;
}

#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h>

#include "../inc/log.h"
#include "../inc/compel_handler.h"

/* --------------------------------------------------------------------
 * Defines
 * -------------------------------------------------------------------*/
#define COMPEL_LOG_LEVEL COMPEL_LOG_ERROR

/* --------------------------------------------------------------------
 * Local Functions declaration
 * -------------------------------------------------------------------*/
static int __compel_prepare_infection(compel_handler *cmpl_hdl, pid_t pid);
static int __compel_disinfection(compel_handler *cmpl_hdl);
static int __compel_steal_fd(compel_handler *cmpl_hdl, int cmd, int *traceeFd);
static int _compel_steal_fd(popsgx_child *tracee, compel_fd fd_type, int *fd,  void* addr, int no_pages);

/* --------------------------------------------------------------------
 * Local Functions definitions
 * -------------------------------------------------------------------*/

/**
 * @brief a function which will be called from compel
 * 
 * @param lvl 
 * @param fmt 
 * @param parms 
 */
static void print_vmsg(unsigned int lvl, const char *fmt, va_list parms)
{
	log_debug("\tLC%u: ", lvl);
	vprintf(fmt, parms);
}

/**
 * @brief Local function for stealing the descriptor
 * 
 * @param cmpl_hdl 
 * @param cmd 
 * @param traceeFd 
 * @return int 
 */
static int __compel_steal_fd(compel_handler *cmpl_hdl, int cmd, int *traceeFd){
    int ret  = 0;

    log_debug("Stealing the %d fd from the victim pid %d", cmd, cmpl_hdl->pid);
    if(!compel_rpc_call(cmd, cmpl_hdl->ctl)){
        if(!compel_util_recv_fd(cmpl_hdl->ctl, traceeFd)){
            if(compel_rpc_sync(cmd, cmpl_hdl->ctl)){
                log_error("Couldn't finalize the command %d", cmd);
                goto fail_compel_stealFd;
            }
        }else{
            log_error("Could not receive the %d fd", cmd);
            goto fail_compel_stealFd;
        }
    }else{
        log_error("Cannot run the command %d", cmd);
        goto fail_compel_stealFd;
    }

return ret;

fail_compel_stealFd:
    return -1;
}

/**
 * @brief Preparing the compel for infection
 * 
 * @param cmpl_hdl Handle for the compel
 * @param pid       Process id for which to execute the compel
 * @return int      error
 */
static int __compel_prepare_infection(compel_handler *cmpl_hdl, pid_t pid){
    int ret = 0;
    int state;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;  

    if(cmpl_hdl == NULL){
        log_error("Infect Handle is NULL");
        return -1;
    }

    memset(cmpl_hdl, 0, sizeof(compel_handler));
    cmpl_hdl->pid = pid;
    
    log_info("Stoping the tracee for compel code injection");
    state = compel_stop_task(pid);
    if(state < 0){
        log_error("Could not stop the victim for compel infection");
        return state;
    }
    cmpl_hdl->state = state;

    log_debug("Preparing compel's parasitic context");
    ctl = compel_prepare(pid);
    if(!ctl){
        log_error("Could not create compel context");
        goto fail_compel_create_context;
    }
    cmpl_hdl->ctl = ctl;

    /*
     * First -- the infection context. Most of the stuff
     * is already filled by compel_prepare(), just set the
     * log descriptor for parasite side, library cannot
     * live w/o it.
     */
    ictx = compel_infect_ctx(cmpl_hdl->ctl);
    ictx->log_fd = STDERR_FILENO;

    log_debug("Preparing the parasite code header for injection");
    parasite_setup_c_header(cmpl_hdl->ctl);

    log_debug("Infecting the tracee through code injection");
    if(compel_infect(cmpl_hdl->ctl, 1, sizeof(int))){
        log_error("Could not infect the tracee");
        goto fail_compel_prepare_infection;
    }

    return ret;

fail_compel_prepare_infection:
    log_info("Curing the victim");
    compel_cure(cmpl_hdl->ctl);
fail_compel_create_context:
    log_info("Resuming the tracee");
    compel_resume_task(pid, cmpl_hdl->state,cmpl_hdl->state);
    cmpl_hdl->state = -1;
    return -1;
}

/**
 * @brief Disinfects the tracee post infection
 * 
 * @param cmpl_hdl 
 * @return int 
 */
static int __compel_disinfection(compel_handler *cmpl_hdl){
    int ret = 0;
    struct infect_ctx *ictx;

    log_debug("Curing the victim");
    if(compel_cure(cmpl_hdl->ctl)){
        ret = -1;
        log_error("Could not cure the victim");
    }

    /*
     *socket has to be closed in order for the consecutive
     *compel calls to work like compel_victim_madvise after compel_victim_stealFd
     */
    ictx = compel_infect_ctx(cmpl_hdl->ctl);
    close(ictx->sock);

    log_debug("Resuming the victim for normal execution");
    if(compel_resume_task(cmpl_hdl->pid, cmpl_hdl->state, cmpl_hdl->state)){
        ret = -1;
        log_error("Could not unseize the victim task");
    }

    memset(cmpl_hdl, 0, sizeof(compel_handler));

    return ret;
}

/**
 * @brief function for stealing fd from the tracee
 * @param tracee popsgx_child structure of the tracee
 * @param fd_type type of the fd to steal
 * @param fd the stolen fd
 * @return error 
 */
static int _compel_steal_fd(popsgx_child *tracee, compel_fd fd_type, int *fd,  void* addr, int no_pages){
    int rc = 0;
    compel_handler cmpl_hdl;
    uint64_t *compel_arg;

    //compel_log_init(print_vmsg, COMPEL_LOG_LEVEL);
    if(tracee == NULL){
        log_debug("The tracee handle given is NULL");
        rc = -1;
        goto out_fail;
    }

    pthread_mutex_lock(&tracee->mutex);

    rc = __compel_prepare_infection(&cmpl_hdl, tracee->c_pid);
    if(rc){
        log_error("Could not prepare infection on tracee");
        goto out_infection_fail;
    }

    if(fd_type == PARASITE_STDUFLT_FD){
        compel_arg = compel_parasite_args(cmpl_hdl.ctl,                                                              \
                                  sizeof((uint64_t)addr) + sizeof(no_pages));
        compel_arg[0] = (uint64_t)addr;
        compel_arg[1] = no_pages;
    }

    rc = __compel_steal_fd(&cmpl_hdl, fd_type, fd);
    if(rc){
        *fd = -1;
        log_error("Could not steal fd");
    }

    rc = __compel_disinfection(&cmpl_hdl);
    if(rc){
        log_error("Could not disinfect tracee");
    }

out_infection_fail:
    pthread_mutex_unlock(&tracee->mutex);
out_fail:
    return rc;
}

/* --------------------------------------------------------------------
 * Public Functions definitions
 * -------------------------------------------------------------------*/
/**
 * @brief Steal uffd from the tracee process
 * 
 * @param tracee 
 * @param fd 
 * @param addr 
 * @param no_pages 
 * @return int 
 */
int compel_steal_uffd(popsgx_child *tracee, int *fd, void* addr, int no_pages){
   return _compel_steal_fd(tracee, PARASITE_STDUFLT_FD, fd, addr, no_pages);
}

/**
 * @brief Steal fd of any kind except uffd
 * 
 * @param tracee 
 * @param fd_type 
 * @param fd 
 * @return int 
 */
int compel_steal_fd(popsgx_child *tracee, compel_fd fd_type, int *fd){
    
    if(fd_type == PARASITE_STDUFLT_FD){
        log_error("Could not steal uffd");
        return -1;
    }

    return _compel_steal_fd(tracee, fd_type, fd, -1, -1);
}
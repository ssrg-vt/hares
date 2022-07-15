#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "../inc/log.h"
#include "../inc/dsm_handler.h"

/* --------------------------------------------------------------------
 * Global variables
 * -------------------------------------------------------------------*/
dsm_handler *dsm = NULL;

 /* --------------------------------------------------------------------
 * Local Functions declarations
 * -------------------------------------------------------------------*/
static int __connect_as_client(char *remote_ip, int remote_port, int *socket_fd);
static int __connect_as_server(int host_port, int *socket_fd);

/* --------------------------------------------------------------------
 * Local functions
 * -------------------------------------------------------------------*/
static int __connect_as_client(char *remote_ip, int remote_port, int *socket_fd){
    int ret = 0;
    int sk = 0;
    
    struct sockaddr_in addr;
    sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
        log_error("Failed on creating a socket");
        ret = sk;
		goto out_socket_err;
	}

    log_info("Connecting as a client to %s:%d", remote_ip, remote_port);

    memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

    ret = inet_aton(remote_ip, &addr.sin_addr);
	if (ret < 0) {
		goto out_close_socket;
	}

    addr.sin_port = htons(remote_port);

    ret = connect(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		goto out_close_socket;
	}

    log_info("Connection established with the server");

    *socket_fd = sk;

    return ret;

out_close_socket:
	close(sk);
out_socket_err:
	return ret;
}

static int __connect_as_server(int host_port, int *socket_fd){
    int ret = 0;
    int sk, ask;
    struct sockaddr_in addr;
    
    sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		log_error("Failed on creating a socket");
        ret = sk;
        goto connect_as_server_failed;
	}

    memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(host_port);

    log_info("Establishing the node as server at port %d", host_port);
    ret = bind(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		log_error("Binding to the port failed");
        goto connect_as_server_bind_failed;
	}

    ret = listen(sk, 16);
	if (ret < 0) {
		log_error("Listening on the port failed");
        goto connect_as_server_bind_failed;
	}

    log_info("Server waiting for connections");

    ask = accept(sk, NULL, NULL);
	if (ask < 0) {
        ret = ask;
		log_error("Server accept failed");
        goto connect_as_server_bind_failed;
	}

    log_info("Connection established with client");

    *socket_fd = ask;

    close(sk);
    return ret;

connect_as_server_bind_failed:
    close(sk);
connect_as_server_failed:
    return ret;
}

int dsm_main(dsm_handler *mdsm, int mode){
    int rc = 0;
    dsm_bus_handler *dsm_bus = &mdsm->dsm_bus;
    
    if(mdsm == NULL){
        log_error("The mdsm is NULL");
        rc = -1;
        goto out_fail;
    }

    //Assigning the global variable dsm
    dsm = mdsm;

    
    if(mode == CLIENT){
        rc = __connect_as_client(dsm->remote_ip, dsm->remote_port, &dsm->socket_fd);
        if(rc){
            log_error("Couldn't establish communication as client");
            goto out_fail;
        }
    }else if(mode == SERVER){
        log_info("Setting up the node as server");
        rc = __connect_as_server(dsm->host_port, &dsm->socket_fd);
        if(rc){
            log_error("Couldn't establish communication as server");
            goto out_fail;
        }
    }

    dsm_bus->args.dsm_sock = dsm->socket_fd;
    dsm_bus->args.msi = &dsm->msi; 
    rc = start_dsm_bus_handler(dsm_bus);
    if(rc){
        log_error("Couldn't start the dsm bus thread");
        goto out_dsm_bus_fail;
    }

    return rc;

out_dsm_bus_fail:
    close(&dsm->socket_fd);
out_fail:
    return rc;
}
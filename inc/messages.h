#ifndef __MESSAGES_H__
#define __MESSAGES_H__
#include <stdint.h>
#include "ptrace.h"

enum msi_message_type
{
	CONNECTION_ESTABLISHED = 0,
	DISCONNECT,
	INVALID_STATE_READ,
	PAGE_REPLY,
	INVALIDATE,
	INVALIDATE_ACK,
	TOTAL_MESSAGES,
	REMOTE_EXECUTE,
	REMOTE_REGS,
	REMOTE_REGS_REPLY,
	VMA_FROM_REMOTE,
	VMA_FROM_REMOTE_ACK,
	VMA_BUFFER_HEADER,
	VMA_BUFFER_HEADER_ACK,
	VMA_BUFFER,
	VMA_BUFFER_ACK,
	VMA_TRANS_ACK
};


/* Different types of payloads defined here*/
struct memory_pair
{
	uint64_t address;
	uint64_t size;
};

struct user_regs{
	struct user_regs_struct regs;
};

struct command_ack
{
	int err;
};

struct request_page
{
	uint64_t address;
	uint64_t size;
};

struct invalidate_page
{
	uint64_t address;
};

struct vma_page{
	char page_data[4096];
};

struct vma_buffer_header{
	uint64_t vma_address;
	uint64_t size;
};

struct vma_header
{
	uint64_t no_vma;
};

struct remote_request_header{
	uint64_t instr_address;
};

/* Message payload and its structure */
union message_payload
{
	struct memory_pair memory_pair;
	struct command_ack command_ack;
	struct request_page request_page;
	struct invalidate_page invalidate_page;
	struct user_regs regs_message;
	struct vma_header vma_header_message;
	struct vma_buffer_header vma_buffer_message;
	struct remote_request_header remote_request_message;
	char page_data[4096];
};

struct msi_message
{
	enum msi_message_type message_type;
	union message_payload payload;
};

//struct msi_page_data_payload
//{
//	enum msi_message_type message_type;
//	char payload[4096];
//};

#endif

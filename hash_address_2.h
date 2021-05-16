#ifndef XMSS_HASH_ADDRESS_2_H
#define XMSS_HASH_ADDRESS_2_H

#include <stdint.h>

#define XMSS_ADDR_TYPE_OTS 0
#define XMSS_ADDR_TYPE_LTREE 1
#define XMSS_ADDR_TYPE_HASHTREE 2

uint32_t get_layer_addr(uint32_t addr[8]);
uint64_t get_tree_addr(uint32_t addr[8]);
uint32_t get_type(uint32_t addr[8]);
uint32_t get_key_and_mask(uint32_t addr[8]);
/* These functions are used for OTS addresses. */
uint32_t get_ots_addr(uint32_t addr[8]);
uint32_t get_chain_addr(uint32_t addr[8]);
uint32_t get_hash_addr(uint32_t addr[8]);
/* This function is used for L-tree addresses. */
uint32_t get_ltree_addr(uint32_t addr[8]);
/* These functions are used for hash tree addresses. */
uint32_t get_tree_height(uint32_t addr[8]);
uint32_t get_tree_index(uint32_t addr[8]);
#endif

#include <stdint.h>

uint32_t get_layer_addr(uint32_t addr[8])
{
    return addr[0];
}
uint64_t get_tree_addr(uint32_t addr[8])
{
	uint64_t tree = (uint64_t)addr[1];
	tree <<= 32;
	tree |= addr[2];
    return tree;
}
uint32_t get_type(uint32_t addr[8])
{
    return addr[3];
}
uint32_t get_key_and_mask(uint32_t addr[8])
{
    return addr[7];
}
/* These functions are used for OTS addresses. */
uint32_t get_ots_addr(uint32_t addr[8])
{
    return addr[4];
}
uint32_t get_chain_addr(uint32_t addr[8])
{
    return addr[5];
}
uint32_t get_hash_addr(uint32_t addr[8])
{
    return addr[6];
}
/* This function is used for L-tree addresses. */
uint32_t get_ltree_addr(uint32_t addr[8])
{
    return addr[4];
}
/* These functions are used for hash tree addresses. */
uint32_t get_tree_height(uint32_t addr[8])
{
    return addr[5];
}
uint32_t get_tree_index(uint32_t addr[8])
{
    return addr[6];
}

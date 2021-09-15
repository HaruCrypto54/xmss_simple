#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "hash.h"
#include "hash_address.h"
#include "hash_address_2.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "utils.h"
#include "xmss_core.h"

/*
1 If you want to speed up by increasing the state size, predefine WOTS_SIG_IN_STATE.
  Then, a state includes WOTS signature in each layer.
  #define WOTS_SIG_IN_STATE

2 If you want to reduce run time for key generation (2^{h/d-1} leaf computations are reduced), predegine FAST_KEYGEN.
  #define FAST_KEYGEN
*/

// #define SAFE_MODE //for debug

#define FAST_KEYGEN
#define SK_MT_BYTES ( params->index_bytes + (4 * params->n) )

#define SIG_XMSS_BYTES ( params->wots_sig_bytes + (params->tree_height * params->n) )

#ifdef WOTS_SIG_IN_STATE
	#define SIG_WOTS_BYTES ( ((params->full_height + 7) >> 3) + params->wots_sig_bytes )
#else
	#define SIG_WOTS_BYTES 0
#endif

#define BDS_BYTES ( (params->tree_height * params->n)\
	 			  + 1 + ( (params->tree_height - 1) * (params->n + 1) )\
	 			  + ( params->tree_height * (params->n + 1 + ((params->full_height + 7) >> 3)) )\
	 			  + ( (params->tree_height>>1) * params->n) )

#define MMT_BYTES ((params->tree_height * params->n)\
				  + 1 + ( params->tree_height * (params->n + 1) )\
				  + ( params->tree_height * (1 + ((params->full_height + 7) >> 3)) )\
				  + SIG_WOTS_BYTES )
				  
// Treehash instance
typedef struct {
	unsigned char *node;
	unsigned char fin;
	uint64_t idx;
} treehash_type;
// Stack
typedef struct {
	unsigned char size;
	unsigned char *node;
	unsigned char *nodeheight;
} stack_type;
// bds/mmt state
typedef struct {
	unsigned char *auth;
	stack_type *stack;
	treehash_type *treehash;
	unsigned char *keep;
#ifdef WOTS_SIG_IN_STATE	
	uint32_t counter_wots_sig;//Count #times this WOTS+ signature is used. Before overuse, update it.
	unsigned char *wots_sig;//Since the same WOTS+ signature is used multiple times, we keep it in state.
#endif
} state_type;
/*Get height of the first left parent*/
static uint32_t get_tau(
	const xmss_params *params,
	const uint32_t idx_leaf)
{
	uint32_t i = 0;
	while (((idx_leaf >> i) & 1) == 1 && i < params->tree_height) {
		i++;
	}
	return i;
}
//Regular pop operation on stack
static void stack_pop(
	const xmss_params *params,
	stack_type *stack,
	unsigned char *pop_node)
{
	stack->size--;
	memcpy(pop_node, stack->node + stack->size * params->n, params->n);
	memset(stack->node + stack->size * params->n, 0, params->n);
	stack->nodeheight[stack->size] = 0;
}
//Regular push operation on stack
static void stack_push(
	const xmss_params *params,
	stack_type *stack,
	unsigned char *push_node, unsigned char push_nodeheight)
{
	memcpy(stack->node + stack->size * params->n, push_node, params->n);
	stack->nodeheight[stack->size] = push_nodeheight;
	stack->size++;
}
//Computes a leaf node from a WOTS public key using an L-tree.
//See RFC8391.
 void ltree(const xmss_params *params,
                   unsigned char *leaf, unsigned char *wots_pk,
                   const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned int len = params->wots_len;
    uint32_t i;

    set_tree_height(addr, 0);
    while (len > 1) {
        for (i = 0; i < len >> 1; i++) {
            set_tree_index(addr, i);
            thash_h(params, wots_pk + i*params->n,
                           wots_pk + (2 * i) * params->n, pub_seed, addr);
        }
        if (len & 1) {
            memcpy(wots_pk + (len >> 1)*params->n,
                   wots_pk + (len - 1)*params->n, params->n);
        }
        len = (len + 1) >> 1;
        set_tree_height(addr, get_tree_height(addr) + 1);
    }
    memcpy(leaf, wots_pk, params->n);
}
// Given leaf index i and height of root node s, computes the root node using treehash algorithm.
//See RFC8391.
static void tree_hash(
	const xmss_params *params,
	unsigned char *root,//output
	const unsigned char *sk,
	uint32_t s,
	uint32_t t,
	const uint32_t subtree_addr[8])
{
	uint32_t i;
	const unsigned char * pub_seed = sk + params->index_bytes + 3 * params->n;
	const unsigned char * sk_seed = sk + params->index_bytes;
	stack_type stack;
	unsigned char stack_node[(t + 1) * params->n];
	unsigned char stack_height[t + 1];	
	unsigned char node[params->n];
	unsigned char wots_pk[params->wots_sig_bytes];
	unsigned char thash_h_in[2 * params->n];
	uint32_t ots_addr[8] = { 0 };
	uint32_t ltree_addr[8] = { 0 };
	uint32_t node_addr[8] = { 0 };

	//1 Init    
	//1.1. Init 3 addresses.    
	copy_subtree_addr(ots_addr, subtree_addr);
	copy_subtree_addr(ltree_addr, subtree_addr);
	copy_subtree_addr(node_addr, subtree_addr);
	set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
	set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
	set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);
	//1.2. Init stack.
	stack.size = 0;
	stack.node = stack_node;
	stack.nodeheight = stack_height;
	//2 Compute root.
	for (i = 0; i < (uint32_t)(1 << t); i++) {
	//2.1. Compute a leaf.
		set_ltree_addr(ltree_addr, s + i);
		set_ots_addr(ots_addr, s + i);
		//gen_leaf_wots(params, node, sk_seed, pub_seed, ltree_addr, ots_addr);
		wots_pkgen(params, wots_pk, sk_seed, pub_seed, ots_addr);
    	ltree(params, node, wots_pk, pub_seed, ltree_addr);
	//2.2. Repeat t_hash while node and top of the stack have the same height.
		set_tree_height(node_addr, 0);
		set_tree_index(node_addr, i + s);
		while (stack.size > 0 && stack.nodeheight[stack.size - 1] == get_tree_height(node_addr)) {
			set_tree_index(node_addr, (get_tree_index(node_addr) - 1) >> 1);
			stack_pop(params, &stack, thash_h_in);
			memcpy(thash_h_in + params->n, node, params->n);
			thash_h(params, node, thash_h_in, pub_seed, node_addr);
			set_tree_height(node_addr, get_tree_height(node_addr) + 1);
		}
		stack_push(params, &stack, node, get_tree_height(node_addr));
	}
	stack_pop(params, &stack, root);
}
// Given leaf index i, generate XMSS signature from state.
// WOTS signature generation + copy authentication path in state.
static void tree_sig(
	const xmss_params *params,
	unsigned char *sig,//output
	const unsigned char *M,
	const unsigned char *sk,
	const uint32_t idx_leaf,
	const uint32_t subtree_addr[8],
	const state_type *state)
{
	const unsigned char * pub_seed = sk + params->index_bytes + 3 * params->n;
	const unsigned char * sk_seed = sk + params->index_bytes;
	uint32_t ots_addr[8] = { 0 };

	//1 Init    
	//1.1. Init address.  
	copy_subtree_addr(ots_addr, subtree_addr);
	set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
	//2. Generate WOTS signature.
	set_ots_addr(ots_addr, idx_leaf);
	wots_sign(params, sig, M, sk_seed, pub_seed, ots_addr);
	//3. Copy auth to sig.
	memcpy(sig + params->wots_sig_bytes, state->auth, params->tree_height * params->n);
}
// Given leaf index i and stack, generate leaf and compute hash value of leaf and top node 
// while leaf (or hash value) and top node have the same height. Afterword, push the result on the stack.
static void update_treehash(
	const xmss_params *params,
	const unsigned char *sk,
	const uint32_t target_height,
	state_type * state,
	const uint32_t layer)
{
	const unsigned char * pub_seed = sk + params->index_bytes + 3 * params->n;
	unsigned char node[2 * params->n];
	unsigned char thash_h_in[2 * params->n];
	uint32_t addr[8] = { 0 };
	uint64_t idx_tree = (state->treehash + target_height)->idx >> params->tree_height;
	uint32_t idx_leaf = (uint32_t)((state->treehash + target_height)->idx & ((1ULL << params->tree_height) - 1ULL));
			
	//1 Init   
	//1.1. Init an address.  
	set_layer_addr(addr, layer);
	set_tree_addr(addr, idx_tree);
	set_type(addr, XMSS_ADDR_TYPE_HASHTREE);
	set_tree_height(addr, 0);
	set_tree_index(addr, idx_leaf);
	//2. Generate a leaf
	tree_hash(params, node, sk, idx_leaf, 0, addr);
	while (state->stack->size > 0 && state->stack->nodeheight[state->stack->size - 1] == get_tree_height(addr)
		&& get_tree_height(addr) < target_height) 
	{
		set_tree_index(addr, (get_tree_index(addr) - 1) >> 1);
		stack_pop(params, state->stack, thash_h_in);
		memcpy(thash_h_in + params->n, node, params->n);
		thash_h(params, node, thash_h_in, pub_seed, addr);
		set_tree_height(addr, get_tree_height(addr) + 1);
	}
	//3. Node does not reach target height, push node on stack and increase idx by 1.
	if (get_tree_height(addr) < target_height){
		stack_push(params, state->stack, node, get_tree_height(addr));
		(state->treehash + target_height)->idx++;
	//4. Node reaches target height, treehash instance is completed.
	} else {
		(state->treehash + target_height)->fin = 1;
		(state->treehash + target_height)->idx = 0;
		if (layer == 0){
			memcpy((state->treehash + target_height)->node ,node, params->n);
		} else {
			stack_push(params, state->stack, node, get_tree_height(addr));
		}
	}
}

//Given XMSS signature, return root of XMSS tree.
//See RFC8391.
void xmss_root_from_sig(
	const xmss_params *params,
	unsigned char *root,//output
	const uint32_t idx_leaf,
	const unsigned char *sig,
	const unsigned char *msg,//must be hashed
	const unsigned char *pub_seed,
	const uint32_t subtree_addr[8]
)
{
	unsigned char wots_pk[params->wots_sig_bytes];
	unsigned char leaf[params->n];
	uint32_t ots_addr[8] = { 0 };
	uint32_t ltree_addr[8] = { 0 };
	uint32_t node_addr[8] = { 0 };
	unsigned char thash_h_in[2 * params->n];
	uint32_t k;
	
	//1. Init
	//1.1. Init 3 addresses.
	copy_subtree_addr(ots_addr, subtree_addr);
	copy_subtree_addr(ltree_addr, subtree_addr);
	copy_subtree_addr(node_addr, subtree_addr);
	set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
	set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
	set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);
	//2. Compute leaf (WOTS public key).
	set_ots_addr(ots_addr, idx_leaf);
	wots_pk_from_sig(params, wots_pk, sig, msg, pub_seed, ots_addr);
	set_ltree_addr(ltree_addr, idx_leaf);
	ltree(params, leaf, wots_pk, pub_seed, ltree_addr);
	//3. Traversal from leaf using auth in signature.
	set_tree_index(node_addr, idx_leaf);
	memcpy(root, leaf, params->n);
	for (k = 0; k < params->tree_height; k++) {
        set_tree_height(node_addr, k);
        if (!((idx_leaf >> k) & 1)){
        	set_tree_index(node_addr, get_tree_index(node_addr) >> 1);
        	memcpy(thash_h_in            , root                                          , params->n);
        	memcpy(thash_h_in + params->n, sig + params->wots_sig_bytes + (k * params->n), params->n);
    	}else{
        	set_tree_index(node_addr, (get_tree_index(node_addr) - 1) >> 1);
        	memcpy(thash_h_in            , sig + params->wots_sig_bytes + (k * params->n), params->n);
        	memcpy(thash_h_in + params->n, root                                          , params->n);  	
    	}
    	thash_h(params, root, thash_h_in, pub_seed, node_addr); 
    }
}
// Generate bds state from secret key.
static void bds_stateGen(
	const xmss_params *params,
	unsigned char *sk,
	state_type * state
)
{
	unsigned int i;
	unsigned char thash_h_in[2 * params->n];
	uint32_t addr[8] = { 0 };
	const unsigned char * pub_seed = sk + params->index_bytes + 3 * params->n;

	//1.Init
	//1.1. Init address.
	set_type(addr, XMSS_ADDR_TYPE_HASHTREE);
	//2.Generate authentication path
	//2.1. auth[0]
	tree_hash(params, state->auth, sk, 1, 0, addr);
	//2.2. auth[1]...auth[h/d-1] and treehash[0]...treehash[h/d-1]
	for (i = 0; i < params->tree_height - 1; i++) {
	//2.2.1. treehash[i]
		tree_hash(params, (state->treehash + i)->node, sk, 3 * (1 << i), i, addr);
		(state->treehash + i)->fin = 1;
	//2.2.2. auth[i]
		tree_hash(params, thash_h_in,                  sk, 2 * (1 << i), i, addr);
		memcpy(thash_h_in + params->n, (state->treehash + i)->node, params->n);
		set_tree_height(addr, i);
		set_tree_index(addr, 1);
		thash_h(params, state->auth + (i + 1) * params->n, thash_h_in, pub_seed, addr);
	}
	//3. Init other entries.
	state->stack->size = 0;
	memset(state->stack->node, 0, (params->tree_height - 1) * params->n);
	memset(state->stack->nodeheight, 0, params->tree_height - 1);
	memset(state->keep, 0, (params->tree_height >> 1) * params->n);	
	//4. Initialization of highest instance of h/d - 1 in the next XMSS tree.
	if (params->d > 1){
#ifdef FAST_KEYGEN
	// Execute h/(2d)+1 treehash upadates on highest treehash instance.
	// This computation prevents the other instances from popping nodes of this instance.
		(state->treehash + params->tree_height - 1)->fin = 0;
		(state->treehash + params->tree_height - 1)->idx = 3 * (1 << (params->tree_height - 1));
		for (i = 0; i < ((params->tree_height + 1) >> 1) + 1 
						&& (state->treehash + params->tree_height - 1)->fin == 0; i++) {
			update_treehash(params, sk, params->tree_height - 1, state, 0);
		}
#else
    // Highest treehash instance generates its target node.
    // This requires 2^{h/d-1} leaf computations. If you want to avoid it predefine FASR_KEYGEN.
		(state->treehash + params->tree_height - 1)->fin = 1;
		set_tree_addr(addr, 1);
		tree_hash(params, (state->treehash + params->tree_height - 1)->node, 
			sk, 3 * (1 << (params->tree_height - 1)), params->tree_height - 1, addr);
#endif
	}else{
	// The highest instance of h/d - 1  has no meaning in XMSS. Kill the functionality.
		(state->treehash + params->tree_height - 1)->fin = 1;
	}
	

}
// Generate mmt state from secret key.
static void mmt_stateGen(
	const xmss_params *params,
	unsigned char *sk,
	state_type * state,
	uint32_t layer
)
{
	unsigned int i;
	uint32_t addr[8] = { 0 };

	//1.Init
	//1.1. Set address.
	set_type(addr, XMSS_ADDR_TYPE_HASHTREE);
	set_layer_addr(addr, layer);
	//2. Generate authentication path
	for (i = 0; i < params->tree_height; i++) {
		tree_hash(params, state->auth + i * params->n, sk, (1 << i), i, addr);
		(state->treehash + i)->fin = 1;
		(state->treehash + i)->idx = 0;
	}
	//3. Init treehash instance of 0.
	state->treehash->fin = 0;
	//4. Init other entries.
	state->stack->size = 0;
	memset(state->stack->node, 0, params->tree_height * params->n);
	memset(state->stack->nodeheight, 0, params->tree_height);
#ifdef WOTS_SIG_IN_STATE
	state->counter_wots_sig = 0;
	memset(state->wots_sig, 0, params->wots_sig_bytes);
#endif
}
// Update bds state after signature generation.
static void bds_state_update(
	const xmss_params *params,
	unsigned char *sk,
	state_type * state
)
{
	uint32_t i, j;
	uint64_t idx_tmp, idx_tree, idx_sig = 0;
	uint32_t idx_leaf;
	unsigned char thash_h_in[2 * params->n];
	uint32_t addr[8] = { 0 };
	const unsigned char * pub_seed = sk + params->index_bytes + 3 * params->n;
	uint32_t tau;

	//1.Init
	//1.1. Init indices.
	for (i = 0; i < params->index_bytes; i++) {
		idx_sig |= ((uint64_t)sk[i]) << 8 * (params->index_bytes - 1 - i);
	}
	idx_tree = (uint64_t)(idx_sig >> params->tree_height);
	idx_leaf = (uint32_t)((idx_sig & ((1ULL << params->tree_height) - 1ULL)));
	//1.2. Set address.
	set_tree_addr(addr, idx_tree);
	set_type(addr, XMSS_ADDR_TYPE_HASHTREE);
	//2. Compute tau, i.e., height of the first left parent of leafnode.
	tau = get_tau(params, idx_leaf);
	//3. Backup keep[(tau-1)>>1]
	if (tau > 0) {
		memcpy(thash_h_in, state->auth + (tau - 1) * params->n, params->n);
		memcpy(thash_h_in + params->n, state->keep + ((tau - 1) >> 1) * params->n, params->n);
	}
	//4. Kepp auth[tau] in keep.
	if (!((idx_leaf >> (tau + 1)) & 1) && (tau < params->tree_height - 1)) {
		memcpy(state->keep + (tau >> 1) * params->n, state->auth + tau * params->n, params->n);
	}
	//5. if tau = 0, generate auth[0].
	if (tau == 0) {
		tree_hash(params, state->auth, sk, idx_leaf, 0, addr);
	}
	//6. if tau > 0, 
	else {
	//6.1. Compute a hash value of keep[(tau-1)>>1] and auth[tau-1] to get new auth[tau].
		if (tau < params->tree_height) {
			set_tree_height(addr, tau - 1);
			set_tree_index(addr, idx_leaf >> tau);
			thash_h(params, state->auth + tau * params->n, thash_h_in, pub_seed, addr);
		}
	//6.2. Copy treehash.node to auth and initialize copied treehash instances from 0 to tau-1.
		for (j = 0; j < tau; j++) {
			memcpy(state->auth + j * params->n, (state->treehash + j)->node, params->n);
			memset((state->treehash + j)->node, 0, params->n);
			idx_tmp = ((uint64_t)idx_sig + 1ULL + 3ULL * (1ULL << j));
			if (idx_tmp < (uint64_t)(1ULL << params->full_height)) {
				(state->treehash + j)->idx = idx_tmp;
				(state->treehash + j)->fin = 0;
			}
		}
	}
#ifdef SAFE_MODE
	// Check if nodes are correctly pushed with respect to their heights.
	for (i=0; i < state->stack->size; ++i){
		if(tau>1 && state->stack->nodeheight[i] < tau-1) {
			exit(0);
		}
	}
#endif
	//7. Treehash updates.
	for (i = 0; i < (params->tree_height + 1) >> 1; i++) {
	//7.1. Get the lowest unfinished treehash instance.
		j = 0;
		while ((state->treehash + j)->fin == 1 && j < params->tree_height) {
			j++;
		}
	//7.2. Update treehash[j] and stack if needed.
		if (j < params->tree_height) {
			update_treehash(params, sk, j, state, 0);
		} else {
			i = (params->tree_height + 1) >> 1;
		}
	}
}
// Update mmt state after signature generation.
static void mmt_state_update(
	const xmss_params *params,
	unsigned char *sk,
	state_type * state,
	uint32_t layer
)
{
	uint32_t i, j;
	uint64_t idx_next, idx_sig = 0;
	uint32_t idx_leaf;
	uint32_t addr[8] = { 0 };
	uint32_t tau1, tau2;
	
	//1.Init
	//1.1. Init indices.
	for (i = 0; i < params->index_bytes; i++) {
		idx_sig |= ((uint64_t)sk[i]) << 8 * (params->index_bytes - 1 - i);
	}
	idx_next = idx_sig + 1ULL;
	idx_sig = (uint64_t)(idx_sig >> (layer * params->tree_height));
	idx_leaf = (uint32_t)((idx_sig & ((1ULL << params->tree_height) - 1ULL)));
	set_type(addr, XMSS_ADDR_TYPE_HASHTREE);
	//2. Update authentication path and initialize treehash instaces.
	if ((idx_next & ((1ULL << (layer * params->tree_height)) - 1ULL)) == 0) {
		tau1 = get_tau(params, idx_leaf);
		for (i = 0; i < (tau1 + 1) && i < params->tree_height; i++) {
			stack_pop(params, state->stack, state->auth + i * params->n);
		}
		tau2 = get_tau(params, idx_leaf + 1);
		for (i = 0; i < (tau2 + 1) && i < params->tree_height; i++) {
			if (i == tau2) {
				(state->treehash + i)->idx = idx_sig + 2ULL - (1ULL << i);
				(state->treehash + i)->fin = 0;
			}
			else if ((idx_sig + 2ULL + (1ULL << i)) <
				(uint64_t)(1ULL << (params->full_height - (layer * params->tree_height)))) {
				(state->treehash + i)->idx = (uint64_t)(idx_sig + 2ULL + (1ULL << i));
				(state->treehash + i)->fin = 0;
			}
		}
	//3. Treehash update (only once).
	}
	else if ((idx_next & ((1ULL << ((layer - 1) * params->tree_height)) - 1ULL)) == 0) {
	//3.1. Get the highest unfinished treehash instance.
		j = params->tree_height;
		while (j > 0 && (state->treehash + j - 1)->fin == 1) {
			j--;
		}
	//3.2. Update treehash[j] and stack if needed.
		if (j > 0) {
			i = j - 1;
			update_treehash(params, sk, i, state, layer);
		}
	}
}
static void state_serialize(
	const xmss_params *params,
	unsigned char *sk, 
	state_type *state,
	unsigned int layer )
{
    unsigned int i;
    
    //auth
	sk += params->tree_height * params->n;
	//stack
	sk[0] = state->stack->size;
	sk ++;
	if(layer == 0){
		sk += (params->tree_height - 1) * (params->n + 1);
	}else{
		sk += params->tree_height * (params->n + 1);
	}
	//treehash
	if(layer == 0){
		sk += params->tree_height * params->n;
	}
    for (i = 0; i < params->tree_height; i++) {
		sk[0] = (state->treehash + i)->fin;
		sk +=  1;
    }
    for (i = 0; i < params->tree_height; i++) {
		ull_to_bytes(sk, ((params->full_height + 7) >> 3), (state->treehash + i)->idx);
		sk += ((params->full_height + 7) >> 3);
    }
#ifdef WOTS_SIG_IN_STATE
	if(layer > 0){
		ull_to_bytes(sk, ((params->full_height + 7) >> 3), state->counter_wots_sig);
	}
#endif
}

static void state_deserialize(
	const xmss_params *params,
	unsigned char *sk,
	state_type * state,
	unsigned int layer )
{
    unsigned int i;
		   
	//auth
	state->auth = sk;
	sk += params->tree_height * params->n;
	//stack
	state->stack->size = sk[0];
	sk++;
	if (layer == 0){
		state->stack->node = sk;
		sk += (params->tree_height - 1) * params->n;
		state->stack->nodeheight =sk;
		sk += params->tree_height - 1;		
	}else{
		state->stack->node = sk;
		sk += params->tree_height * params->n;
		state->stack->nodeheight =sk;
		sk += params->tree_height;	
	}
	//treehash
	if(layer == 0){
    	for (i = 0; i < params->tree_height; i++) {
			(state->treehash + i)->node = sk;
			sk +=  params->n;
    	}
	}
    for (i = 0; i < params->tree_height; i++) {
		(state->treehash + i)->fin = sk[0];
		sk +=  1;
    }
    for (i = 0; i < params->tree_height; i++) {
		(state->treehash + i)->idx = bytes_to_ull(sk, ((params->full_height + 7) >> 3));
		sk +=  ((params->full_height + 7) >> 3);
    }
	if(layer == 0){
		state->keep = sk;
	}
#ifdef WOTS_SIG_IN_STATE
	if(layer > 0){
		state->counter_wots_sig = bytes_to_ull(sk, ((params->full_height + 7) >> 3));
		sk += ((params->full_height + 7) >> 3);
		state->wots_sig = sk;
	}
#endif
}

// Secret key size including states.
unsigned long long xmss_xmssmt_core_sk_bytes(const xmss_params *params)
{
	return SK_MT_BYTES + BDS_BYTES + (params->d - 1) * MMT_BYTES;
}
// Key generation of XMSS^MT
int xmssmt_core_keypair(const xmss_params *params,
	unsigned char *pk, unsigned char *sk)
{
	uint32_t addr[8] = { 0 };
	unsigned char * pub_seed = sk + params->index_bytes + 3 * params->n;
	unsigned int i;
	unsigned char * root = sk + params->index_bytes + 2 * params->n;
	unsigned char leaf[params->n];
	unsigned char thash_h_in[2 * params->n];
	state_type state;
	stack_type stack[1];
	treehash_type treehash[32];

	//1.Init SK without state.
	//1.1. Set idx_MT = 0
	memset(sk, 0, params->index_bytes);
	//1.2. Init SK_SEED and SK_PRF.
	randombytes(sk + params->index_bytes, 2*params->n);
	//1.3. Init PUB_SEED.
	randombytes(pub_seed, params->n);
	//1.4. Memmory allocation od members of state.
	state.stack = stack;
	state.treehash = treehash;
	//2. Generate state.
	//2.1. Generate BDS state.
	state_deserialize(params, sk + SK_MT_BYTES, &state, 0);
	bds_stateGen(params, sk, &state);
	state_serialize(  params, sk + SK_MT_BYTES, &state, 0);
	//2.2. Generate MMT states.
	for (i = 1; i < params->d; i++) {
		state_deserialize(params, sk + SK_MT_BYTES + BDS_BYTES + (i - 1) * MMT_BYTES, &state, i);
		mmt_stateGen(params, sk, &state, i);
		state_serialize(  params, sk + SK_MT_BYTES + BDS_BYTES + (i - 1) * MMT_BYTES, &state, i);
	}
	//3. Generate root of top XMSS tree.
	set_layer_addr(addr, params->d - 1);
	tree_hash(params, leaf, sk, 0, 0, addr);	
	set_type(addr, XMSS_ADDR_TYPE_HASHTREE);
	set_tree_index(addr, 0);
	memcpy(root, leaf, params->n);
	for (i = 0; i < params->tree_height; i++) {
        set_tree_height(addr, i);
        memcpy(thash_h_in            , root                        , params->n);
        memcpy(thash_h_in + params->n, state.auth + (i * params->n), params->n);
    	thash_h(params, root, thash_h_in, pub_seed, addr); 
    }
	//4. Copy root and pub_seed to pk.
	memcpy(pk, root, params->n);
	memcpy(pk + params->n, pub_seed, params->n);
	
	return 0;
}

// Signature generation of XMSS^MT.
int xmssmt_core_sign(const xmss_params *params,
	unsigned char *sk,
	unsigned char *sig, unsigned long long  *sig_len,
	const unsigned char *m, unsigned long long  mlen)
{
	uint64_t idx_sig = 0;
	uint64_t idx_tree;
	uint32_t idx_leaf;
	uint64_t i;
	const unsigned char * sk_prf = sk + params->index_bytes + params->n;
	const unsigned char * pub_root = sk + params->index_bytes + 2 * params->n;
	const unsigned char * pub_seed = sk + params->index_bytes + 3 * params->n;
	unsigned char R[params->n];
	unsigned char msg_h[params->n];
	uint32_t addr[8] = { 0 };
	unsigned char idx_bytes_32[32];
	state_type state;
	stack_type stack[1];
	treehash_type treehash[32];

	//1. Init
	//1.1. Get idecises.
	for (i = 0; i < params->index_bytes; i++) {
		idx_sig |= ((uint64_t)sk[i]) << 8 * (params->index_bytes - 1 - i);
	}
	idx_tree = idx_sig >> params->tree_height;
	idx_leaf = (idx_sig & ((1 << params->tree_height) - 1));
	//1.2. Initi signature length.
	*sig_len = 0;
	//1.3. Set state.
	state.stack = stack;
	state.treehash = treehash;
	//2. Message Hash.
	//2.1.Generate R.
	ull_to_bytes(idx_bytes_32, 32, idx_sig);
	prf(params, R, idx_bytes_32, sk_prf);
	//2.2. Hash computation.
	memcpy(sig + params->sig_bytes, m, mlen);
	hash_message(params, msg_h, R, pub_root, idx_sig,
		sig + params->sig_bytes - params->padding_len - 3 * params->n,
		mlen);
	//3. Copy index to signature
	for (i = 0; i < params->index_bytes; i++) {
		sig[i] = (idx_sig >> 8 * (params->index_bytes - 1 - i)) & 255;
	}
	sig += params->index_bytes;
	*sig_len += params->index_bytes;
	//4. Copy R to signature
	memcpy(sig, R, params->n);
	sig += params->n;
	*sig_len += params->n;
	//5. Signature generation in each layer
	//5.1. Bottom XMSS tree.
	set_layer_addr(addr, 0);
	set_tree_addr(addr, idx_tree);
	state_deserialize(params, sk + SK_MT_BYTES, &state, 0);
	tree_sig(params, sig, msg_h, sk, idx_leaf, addr, &state);
	sig += SIG_XMSS_BYTES;
	*sig_len += SIG_XMSS_BYTES;
	//5.1.1. Update bds state.
	bds_state_update(params, sk, &state);
	state_serialize(params, sk + SK_MT_BYTES, &state, 0);
	//5.2. XMSS trees on higher layers.
	for (i = 1; i < params->d; i++) {
		state_deserialize(params, sk + SK_MT_BYTES + BDS_BYTES + (i - 1) * MMT_BYTES, &state, i);
#ifdef WOTS_SIG_IN_STATE
	//5.2.1. If WOTS signature in state can be used, copy it to XMSS signature. 
		if ((uint64_t)state.counter_wots_sig < (uint64_t)(1ULL << params->tree_height) && state.counter_wots_sig > 0) {
			memcpy(sig, state.wots_sig, params->wots_sig_bytes);
			state.counter_wots_sig++;			
			memcpy(sig + params->wots_sig_bytes, state.auth, params->tree_height * params->n);
	//5.2.2. Generate WOTS signature by treeSig and copy WOTS signature to state.
		}else{
			xmss_root_from_sig(params, msg_h, idx_leaf, sig - SIG_XMSS_BYTES, msg_h, pub_seed, addr);
			idx_leaf = (idx_tree & ((1 << params->tree_height) - 1));
			idx_tree = idx_tree >> params->tree_height;
			set_layer_addr(addr, i);
			set_tree_addr(addr, idx_tree);
			tree_sig(params, sig, msg_h, sk, idx_leaf, addr, &state);
			state.counter_wots_sig = 1;
			memcpy(state.wots_sig, sig, params->wots_sig_bytes);
		}
#else
	//5.2.1. Compute root of XMSS tree a layer below.
		xmss_root_from_sig(params, msg_h, idx_leaf, sig - SIG_XMSS_BYTES, msg_h, pub_seed, addr);
		idx_leaf = (idx_tree & ((1 << params->tree_height) - 1));
		idx_tree = idx_tree >> params->tree_height;
		set_layer_addr(addr, i);
		set_tree_addr(addr, idx_tree);
	//5.2.2. Sign root.
		tree_sig(params, sig, msg_h, sk, idx_leaf, addr, &state);
#endif
		sig += SIG_XMSS_BYTES;
		*sig_len += SIG_XMSS_BYTES;
	//5.2.3. MMT state update.
		mmt_state_update(params, sk, &state, i);
		state_serialize(params, sk + SK_MT_BYTES + BDS_BYTES + (i - 1) * MMT_BYTES, &state, i);
	}
	memcpy(sig, m, mlen);
	*sig_len += mlen;
	//7. Increase idx_sig by 1.
	idx_sig++;
	for (i = 0; i < params->index_bytes; i++) {
		sk[i] = (idx_sig >> 8 * (params->index_bytes - 1 - i)) & 255;
	}
	return 0;
}
int xmss_core_keypair(const xmss_params *params,
	unsigned char *pk, unsigned char *sk)
{
	return xmssmt_core_keypair(params, pk, sk);
}
int xmss_core_sign(const xmss_params *params,
	unsigned char *sk,
	unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen)
{
	return xmssmt_core_sign(params, sk, sm, smlen, m, mlen);
}


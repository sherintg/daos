/**
 * (C) Copyright 2016-2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
#ifndef __DD_OBJ_H__
#define __DD_OBJ_H__

#include <daos/common.h>
#include <daos/tse.h>
#include <daos_obj.h>
#include <daos/metrics.h>

/* EC parity is stored in a private address range that is selected by setting
 * the most-significant bit of the offset (an unsigned long). This effectively
 * limits the addressing of user extents to the lower 63 bits of the offset
 * range.
 */
#define DAOS_EC_PARITY_BIT	(1ULL << 63)

static inline daos_oclass_id_t
daos_obj_id2class(daos_obj_id_t oid)
{
	daos_oclass_id_t ocid;

	ocid = (oid.hi & OID_FMT_CLASS_MASK) >> OID_FMT_CLASS_SHIFT;
	return ocid;
}

static inline daos_ofeat_t
daos_obj_id2feat(daos_obj_id_t oid)
{
	daos_ofeat_t ofeat;

	ofeat = (oid.hi & OID_FMT_FEAT_MASK) >> OID_FMT_FEAT_SHIFT;
	return ofeat;
}

static inline uint8_t
daos_obj_id2ver(daos_obj_id_t oid)
{
	uint8_t version;

	version = (oid.hi & OID_FMT_VER_MASK) >> OID_FMT_VER_SHIFT;
	return version;
}

static inline bool
daos_obj_id_is_nil(daos_obj_id_t oid)
{
	return oid.hi == 0 && oid.lo == 0;
}

/**
 * XXX old class IDs
 *
 * They should be removed after getting rid of all hard-coded
 * class IDs from python tests.
 */
enum {
	DAOS_OC_UNKNOWN,
	DAOS_OC_TINY_RW,
	DAOS_OC_SMALL_RW,
	DAOS_OC_LARGE_RW,
	DAOS_OC_R2S_RW,		/* class for testing */
	DAOS_OC_R2_RW,		/* class for testing */
	DAOS_OC_R2_MAX_RW,	/* class for testing */
	DAOS_OC_R3S_RW,		/* class for testing */
	DAOS_OC_R3_RW,		/* class for testing */
	DAOS_OC_R3_MAX_RW,	/* class for testing */
	DAOS_OC_R4S_RW,		/* class for testing */
	DAOS_OC_R4_RW,		/* class for testing */
	DAOS_OC_R4_MAX_RW,	/* class for testing */
	DAOS_OC_REPL_MAX_RW,
	DAOS_OC_ECHO_R1S_RW,	/* Echo class, 1 replica single stripe */
	DAOS_OC_ECHO_R2S_RW,	/* Echo class, 2 replica single stripe */
	DAOS_OC_ECHO_R3S_RW,	/* Echo class, 3 replica single stripe */
	DAOS_OC_ECHO_R4S_RW,	/* Echo class, 4 replica single stripe */
	DAOS_OC_R1S_SPEC_RANK,	/* 1 replica with specified rank */
	DAOS_OC_R2S_SPEC_RANK,	/* 2 replica start with specified rank */
	DAOS_OC_R3S_SPEC_RANK,	/* 3 replica start with specified rank.
				 * These 3 XX_SPEC are mostly for testing
				 * purpose.
				 */
	DAOS_OC_EC_K2P1_L32K,	/* Erasure code, 2 data cells, 1 parity cell,
				 * cell size 32K.
				 */
	DAOS_OC_EC_K2P2_L32K,	/* Erasure code, 2 data cells, 2 parity cells,
				 * cell size 32K.
				 */
	DAOS_OC_EC_K4P1_L32K,	/* Erasure code, 4 data cells, 1 parity cells,
				 * cell size 32K.
				 */

	DAOS_OC_EC_K4P2_L32K,	/* Erasure code, 4 data cells, 2 parity cells,
				 * cell size 32K.
				 */

	DAOS_OC_EC_K2P1_SPEC_RANK_L32K,
	DAOS_OC_EC_K4P1_SPEC_RANK_L32K,
	/**
	 * Object class reserved by Object Index Table (OIT)
	 * It is the 1st version and could be changed in the future
	 *
	 * NB: it should be smaller than OC_BACK_COMPAT (50)
	 */
	DAOS_OC_OIT_RF0	= 45,
	DAOS_OC_OIT_RF1	= 46,
	DAOS_OC_OIT_RF2	= 47,
	DAOS_OC_OIT_RF3	= 48,
	DAOS_OC_OIT_RF4	= 49,
};

/* Temporarily keep it to minimize change, remove it in the future */
#define DAOS_OC_ECHO_TINY_RW	DAOS_OC_ECHO_R1S_RW

static inline bool
daos_obj_is_echo(daos_obj_id_t oid)
{
	int	oc;

	if (daos_obj_id2feat(oid) & DAOS_OF_ECHO)
		return true;

	oc = daos_obj_id2class(oid);
	return oc == DAOS_OC_ECHO_TINY_RW || oc == DAOS_OC_ECHO_R2S_RW ||
	       oc == DAOS_OC_ECHO_R3S_RW || oc == DAOS_OC_ECHO_R4S_RW;
}

static inline bool
daos_obj_is_srank(daos_obj_id_t oid)
{
	int	oc = daos_obj_id2class(oid);

	return oc == DAOS_OC_R3S_SPEC_RANK || oc == DAOS_OC_R1S_SPEC_RANK ||
	       oc == DAOS_OC_R2S_SPEC_RANK ||
	       oc == DAOS_OC_EC_K2P1_SPEC_RANK_L32K ||
	       oc == DAOS_OC_EC_K4P1_SPEC_RANK_L32K;
}

enum {
	/* smallest cell size */
	DAOS_EC_CELL_MIN	= (4 << 10),
	/* default cell size */
	DAOS_EC_CELL_DEF	= (128 << 10),
	/* largest cell size */
	DAOS_EC_CELL_MAX	= (1024 << 10),
};

static inline bool
daos_ec_cs_valid(uint32_t cell_sz)
{
	if (cell_sz < DAOS_EC_CELL_MIN || cell_sz > DAOS_EC_CELL_MAX)
		return false;

	/* should be multiplier of the min size */
	if (cell_sz % DAOS_EC_CELL_MIN != 0)
		return false;

	return true;
}

enum daos_io_mode {
	DIM_DTX_FULL_ENABLED	= 0,	/* by default */
	DIM_SERVER_DISPATCH	= 1,
	DIM_CLIENT_DISPATCH	= 2,
};

#define DAOS_OBJ_GRP_MAX	(~0)
#define DAOS_OBJ_REPL_MAX	(~0)
#define DAOS_OBJ_RESIL_MAX	(~0)

/**
 * 192-bit object ID, it can identify a unique bottom level object.
 * (a shard of upper level object).
 */
typedef struct {
	/** Public section, high level object ID */
	daos_obj_id_t		id_pub;
	/** Private section, object shard index */
	uint32_t		id_shard;
	/** Padding */
	uint32_t		id_pad_32;
} daos_unit_oid_t;

/** object metadata stored in the global OI table of container */
struct daos_obj_md {
	daos_obj_id_t		omd_id;
	uint32_t		omd_ver;
	uint32_t		omd_padding;
	union {
		uint32_t	omd_split;
		uint64_t	omd_loff;
	};
};

/** object shard metadata stored in each container shard */
struct daos_obj_shard_md {
	/** ID of the object shard */
	daos_unit_oid_t		smd_id;
	uint64_t		smd_attr;
	uint32_t		smd_po_ver;
	uint32_t		smd_padding;
};

struct daos_shard_loc {
	uint32_t	sd_rank;
	uint32_t	sd_tgt_idx;
};

/**
 * object layout information.
 **/
struct daos_obj_shard {
	uint32_t		os_replica_nr;
	struct daos_shard_loc	os_shard_loc[0];
};

struct daos_obj_layout {
	uint32_t		 ol_ver;
	uint32_t		 ol_class;
	uint32_t		 ol_nr;
	struct daos_obj_shard	*ol_shards[0];
};

/**
 * can be used as st_rank to indicate target can be ignored for IO, for example
 * update DAOS_OBJ_REPL_MAX obj with some target failed case.
 */
#define DAOS_TGT_IGNORE		((d_rank_t)-1)
/** to identify each obj shard's target */
struct daos_shard_tgt {
	uint32_t		st_rank;	/* rank of the shard */
	uint32_t		st_shard;	/* shard index */
	uint32_t		st_shard_id;	/* shard id */
	uint32_t		st_tgt_id;	/* target id */
	uint16_t		st_tgt_idx;	/* target xstream index */
	/* target idx for EC obj, only used for client */
	uint16_t		st_ec_tgt;
};

static inline bool
daos_oid_is_null(daos_obj_id_t oid)
{
	return oid.lo == 0 && oid.hi == 0;
}

static inline int
daos_oid_cmp(daos_obj_id_t a, daos_obj_id_t b)
{
	if (a.hi < b.hi)
		return -1;
	else if (a.hi > b.hi)
		return 1;

	if (a.lo < b.lo)
		return -1;
	else if (a.lo > b.lo)
		return 1;

	return 0;
}

static inline bool
daos_unit_obj_id_equal(daos_unit_oid_t oid1, daos_unit_oid_t oid2)
{
	return daos_oid_cmp(oid1.id_pub, oid2.id_pub) == 0 &&
	       oid1.id_shard == oid2.id_shard;
}

struct pl_obj_layout;

int obj_class_init(void);
void obj_class_fini(void);
struct daos_oclass_attr *daos_oclass_attr_find(daos_obj_id_t oid,
					       bool *is_priv);
unsigned int daos_oclass_grp_size(struct daos_oclass_attr *oc_attr);
unsigned int daos_oclass_grp_nr(struct daos_oclass_attr *oc_attr,
				struct daos_obj_md *md);
int daos_oclass_fit_max(daos_oclass_id_t oc_id, int domain_nr, int target_nr,
			daos_oclass_id_t *oc_id_p);
bool daos_oclass_is_valid(daos_oclass_id_t oc_id);
daos_oclass_id_t daos_obj_get_oclass(daos_handle_t coh, daos_ofeat_t ofeats,
				   daos_oclass_hints_t hints, uint32_t args);

/** bits for the specified rank */
#define DAOS_OC_SR_SHIFT	24
#define DAOS_OC_SR_BITS		8
#define DAOS_OC_SR_MASK		\
	(((1ULL << DAOS_OC_SR_BITS) - 1) << DAOS_OC_SR_SHIFT)

/** bits for the specified target, Note: the target here means the target
 * index inside the rank, and it only reserve 4 bits, so only specify 16th
 * target maximum.
 */
#define DAOS_OC_ST_SHIFT	20
#define DAOS_OC_ST_BITS		4
#define DAOS_OC_ST_MASK		\
	(((1ULL << DAOS_OC_ST_BITS) - 1) << DAOS_OC_ST_SHIFT)

static inline d_rank_t
daos_oclass_sr_get_rank(daos_obj_id_t oid)
{
	D_ASSERT(daos_obj_is_srank(oid));
	return ((oid.hi & DAOS_OC_SR_MASK) >> DAOS_OC_SR_SHIFT);
}

static inline daos_obj_id_t
daos_oclass_sr_set_rank(daos_obj_id_t oid, d_rank_t rank)
{
	D_ASSERT(daos_obj_is_srank(oid));
	D_ASSERT(rank < (1 << DAOS_OC_SR_SHIFT));
	D_ASSERT((oid.hi & DAOS_OC_SR_MASK) == 0);

	oid.hi |= (uint64_t)rank << DAOS_OC_SR_SHIFT;
	return oid;
}

static inline int
daos_oclass_st_get_tgt(daos_obj_id_t oid)
{
	D_ASSERT(daos_obj_is_srank(oid));

	return ((oid.hi & DAOS_OC_ST_MASK) >> DAOS_OC_ST_SHIFT);
}

static inline daos_obj_id_t
daos_oclass_st_set_tgt(daos_obj_id_t oid, int tgt)
{
	D_ASSERT(daos_obj_is_srank(oid));
	D_ASSERT(tgt < (1 << DAOS_OC_ST_SHIFT));
	D_ASSERT((oid.hi & DAOS_OC_ST_MASK) == 0);

	oid.hi |= (uint64_t)tgt << DAOS_OC_ST_SHIFT;
	return oid;
}

static inline bool
daos_oclass_is_ec(struct daos_oclass_attr *oca)
{
	return oca->ca_resil == DAOS_RES_EC;
}

static inline void
daos_obj_set_oid(daos_obj_id_t *oid, daos_ofeat_t ofeats,
		 daos_oclass_id_t cid, uint32_t args)
{
	uint64_t hdr;

	/* TODO: add check at here, it should return error if user specified
	 * bits reserved by DAOS
	 */
	oid->hi &= (1ULL << OID_FMT_INTR_BITS) - 1;
	/**
	 * | Upper bits contain
	 * | OID_FMT_VER_BITS (version)		 |
	 * | OID_FMT_FEAT_BITS (object features) |
	 * | OID_FMT_CLASS_BITS (object class)	 |
	 * | 96-bit for upper layer ...		 |
	 */
	hdr  = ((uint64_t)OID_FMT_VER << OID_FMT_VER_SHIFT);
	hdr |= ((uint64_t)ofeats << OID_FMT_FEAT_SHIFT);
	hdr |= ((uint64_t)cid << OID_FMT_CLASS_SHIFT);
	oid->hi |= hdr;
}

/* check if an object ID is OIT (Object ID Table) */
static inline bool
daos_oid_is_oit(daos_obj_id_t oid)
{
	daos_oclass_id_t	oc = daos_obj_id2class(oid);

	return (oc == DAOS_OC_OIT_RF0) || (oc == DAOS_OC_OIT_RF1) ||
	       (oc == DAOS_OC_OIT_RF2) || (oc == DAOS_OC_OIT_RF3) ||
	       (oc == DAOS_OC_OIT_RF4);
}

/*
 * generate ID for Object ID Table which is just an object, caller should
 * provide valid cont_rf value (DAOS_PROP_CO_REDUN_RF0 ~ DAOS_PROP_CO_REDUN_RF4)
 * or it possibly assert it internally
 */
static inline daos_obj_id_t
daos_oit_gen_id(daos_epoch_t epoch, uint32_t cont_rf)
{
	daos_oclass_id_t	oc;
	daos_obj_id_t		oid = {0};

	switch (cont_rf) {
	case DAOS_PROP_CO_REDUN_RF0:
		oc = DAOS_OC_OIT_RF0;
		break;
	case DAOS_PROP_CO_REDUN_RF1:
		oc = DAOS_OC_OIT_RF1;
		break;
	case DAOS_PROP_CO_REDUN_RF2:
		oc = DAOS_OC_OIT_RF2;
		break;
	case DAOS_PROP_CO_REDUN_RF3:
		oc = DAOS_OC_OIT_RF3;
		break;
	case DAOS_PROP_CO_REDUN_RF4:
		oc = DAOS_OC_OIT_RF4;
		break;
	default:
		D_ASSERTF(0, "bad cont_rf %d\n", cont_rf);
		break;
	};

	daos_obj_set_oid(&oid, 0, oc, 0);
	oid.lo = epoch;
	return oid;
}

static inline bool
daos_unit_oid_is_null(daos_unit_oid_t oid)
{
	return oid.id_shard == 0 && daos_oid_is_null(oid.id_pub);
}

static inline int
daos_unit_oid_compare(daos_unit_oid_t a, daos_unit_oid_t b)
{
	int rc;

	rc = daos_oid_cmp(a.id_pub, b.id_pub);
	if (rc != 0)
		return rc;

	if (a.id_shard < b.id_shard)
		return -1;
	else if (a.id_shard > b.id_shard)
		return 1;

	return 0;
}

int daos_obj_layout_free(struct daos_obj_layout *layout);
int daos_obj_layout_alloc(struct daos_obj_layout **layout, uint32_t grp_nr,
			  uint32_t grp_size);
int daos_obj_layout_get(daos_handle_t coh, daos_obj_id_t oid,
			struct daos_obj_layout **layout);

int daos_iod_copy(daos_iod_t *dst, daos_iod_t *src);
void daos_iods_free(daos_iod_t *iods, int nr, bool free);
daos_size_t daos_iods_len(daos_iod_t *iods, int nr);

int daos_obj_generate_oid_by_rf(daos_handle_t poh, uint64_t rf_factor,
				daos_obj_id_t *oid, daos_ofeat_t ofeats,
				daos_oclass_id_t cid, daos_oclass_hints_t hints,
				uint32_t args);

int dc_obj_init(void);
void dc_obj_fini(void);

int dc_obj_register_class(tse_task_t *task);
int dc_obj_query_class(tse_task_t *task);
int dc_obj_list_class(tse_task_t *task);
int dc_obj_open(tse_task_t *task);
int dc_obj_close(tse_task_t *task);
int dc_obj_punch_task(tse_task_t *task);
int dc_obj_punch_dkeys_task(tse_task_t *task);
int dc_obj_punch_akeys_task(tse_task_t *task);
int dc_obj_query(tse_task_t *task);
int dc_obj_query_key(tse_task_t *task);
int dc_obj_sync(tse_task_t *task);
int dc_obj_fetch_task(tse_task_t *task);
int dc_obj_update_task(tse_task_t *task);
int dc_obj_list_dkey(tse_task_t *task);
int dc_obj_list_akey(tse_task_t *task);
int dc_obj_list_rec(tse_task_t *task);
int dc_obj_list_obj(tse_task_t *task);
int dc_obj_fetch_md(daos_obj_id_t oid, struct daos_obj_md *md);
int dc_obj_layout_get(daos_handle_t oh, struct daos_obj_layout **p_layout);
int dc_obj_layout_refresh(daos_handle_t oh);
int dc_obj_verify(daos_handle_t oh, daos_epoch_t *epochs, unsigned int nr);
daos_handle_t dc_obj_hdl2cont_hdl(daos_handle_t oh);

int dc_tx_open(tse_task_t *task);
int dc_tx_commit(tse_task_t *task);
int dc_tx_abort(tse_task_t *task);
int dc_tx_open_snap(tse_task_t *task);
int dc_tx_close(tse_task_t *task);
int dc_tx_restart(tse_task_t *task);
int dc_tx_local_open(daos_handle_t coh, daos_epoch_t epoch,
		     uint32_t flags, daos_handle_t *th);
int dc_tx_local_close(daos_handle_t th);
int dc_tx_hdl2epoch(daos_handle_t th, daos_epoch_t *epoch);

/** Decode shard number from enumeration anchor */
static inline uint32_t
dc_obj_anchor2shard(daos_anchor_t *anchor)
{
	return anchor->da_shard;
}

/** Encode shard into enumeration anchor. */
static inline void
dc_obj_shard2anchor(daos_anchor_t *anchor, uint32_t shard)
{
	anchor->da_shard = shard;
}

enum daos_io_flags {
	/* The RPC will be sent to leader replica. */
	DIOF_TO_LEADER		= 0x1,
	/* The RPC will be sent to specified replica. */
	DIOF_TO_SPEC_SHARD	= 0x2,
	/* The operation (enumeration) has specified epoch. */
	DIOF_WITH_SPEC_EPOCH	= 0x4,
	/* The operation is for EC recovering. */
	DIOF_EC_RECOV		= 0x8,
	/* The key existence. */
	DIOF_CHECK_EXISTENCE	= 0x10,
	/* The RPC will be sent to specified redundancy group. */
	DIOF_TO_SPEC_GROUP	= 0x20,
	/* For data migration. */
	DIOF_FOR_MIGRATION	= 0x40,
	/* For EC aggregation. */
	DIOF_FOR_EC_AGG		= 0x80,
	/* The operation is for EC snapshot recovering */
	DIOF_EC_RECOV_SNAP	= 0x100,
};

/**
 * The type of the packing data for serialization
 */
enum {
	OBJ_ITER_NONE,
	OBJ_ITER_OBJ,
	OBJ_ITER_DKEY,
	OBJ_ITER_AKEY,
	OBJ_ITER_SINGLE,
	OBJ_ITER_RECX,
	OBJ_ITER_DKEY_EPOCH,
	OBJ_ITER_AKEY_EPOCH,
	OBJ_ITER_OBJ_PUNCH_EPOCH,
};

#define RECX_INLINE	(1U << 0)

struct obj_enum_rec {
	daos_recx_t		rec_recx;
	daos_epoch_range_t	rec_epr;
	uint64_t		rec_size;
	uint32_t		rec_version;
	uint32_t		rec_flags;
};

enum daos_recx_type {
	/** normal valid recx */
	DRT_NORMAL	= 0,
	/** hole recx */
	DRT_HOLE	= 1,
	/**
	 * shadow valid recx, only used for EC degraded fetch to indicate
	 * recx on shadow, i.e need-to-be-recovered recx.
	 */
	DRT_SHADOW	= 2,
};

struct daos_recx_ep {
	daos_recx_t	re_recx;
	daos_epoch_t	re_ep;
	uint32_t	re_rec_size;
	uint8_t		re_type;
};

struct daos_recx_ep_list {
	/** #valid items in re_items array */
	uint32_t		 re_nr;
	/** #total items (capacity) in re_items array */
	uint32_t		 re_total;
	/** recovery from snapshot flag */
	bool			 re_snapshot;
	/** epoch valid flag, re_items' re_ep can be ignored when it is false */
	bool			 re_ep_valid;
	struct daos_recx_ep	*re_items;
};

static inline void
daos_recx_ep_free(struct daos_recx_ep_list *list)
{
	if (list->re_items)
		D_FREE(list->re_items);
	list->re_nr = 0;
	list->re_total = 0;
}

static inline void
daos_recx_ep_list_free(struct daos_recx_ep_list *list, unsigned int nr)
{
	unsigned int	i;

	if (list == NULL)
		return;

	for (i = 0; i < nr; i++)
		daos_recx_ep_free(&list[i]);
	D_FREE(list);
}

static inline int
daos_recx_ep_add(struct daos_recx_ep_list *list, struct daos_recx_ep *recx)
{
	struct daos_recx_ep	*new_items;
	uint32_t		 nr;

	if (list->re_total == list->re_nr) {
		nr = (list->re_total == 0) ? 8 : (2 * list->re_total);
		if (list->re_total == 0)
			D_ALLOC_ARRAY(new_items, nr);
		else
			D_REALLOC_ARRAY(new_items, list->re_items,
					list->re_total, nr);
		if (new_items == NULL)
			return -DER_NOMEM;
		list->re_items = new_items;
		list->re_total = nr;
	}

	D_ASSERT(list->re_total > list->re_nr);
	list->re_items[list->re_nr++] = *recx;
	return 0;
}

static inline struct daos_recx_ep_list *
daos_recx_ep_lists_dup(struct daos_recx_ep_list *lists, unsigned int nr)
{
	struct daos_recx_ep_list	*dup_lists;
	struct daos_recx_ep_list	*dup_list, *list;
	unsigned int			 i;

	if (lists == NULL || nr == 0)
		return NULL;

	D_ALLOC_ARRAY(dup_lists, nr);
	if (dup_lists == NULL)
		return NULL;

	for (i = 0; i < nr; i++) {
		list = &lists[i];
		dup_list = &dup_lists[i];
		*dup_list = *list;
		dup_list->re_items = NULL;
		if (list->re_nr == 0)
			continue;
		D_ALLOC_ARRAY(dup_list->re_items, list->re_nr);
		if (dup_list->re_items == NULL) {
			daos_recx_ep_list_free(dup_lists, nr);
			return NULL;
		}
		memcpy(dup_list->re_items, list->re_items,
		       list->re_nr * sizeof(*list->re_items));
	}

	return dup_lists;
}

static inline void
daos_recx_ep_list_hilo(struct daos_recx_ep_list *list, daos_recx_t *hi_ptr,
		       daos_recx_t *lo_ptr)
{
	struct daos_recx_ep		*recx_ep;
	daos_recx_t			*recx;
	daos_recx_t			 hi = {0};
	daos_recx_t			 lo = {0};
	uint64_t			 end, end_hi, end_lo;
	unsigned int			 i;

	if (list == NULL)
		goto out;

	end_hi = 0;
	end_lo = -1;
	for (i = 0; i < list->re_nr; i++) {
		recx_ep = &list->re_items[i];
		recx = &recx_ep->re_recx;
		end = DAOS_RECX_PTR_END(recx);
		if (end > end_hi) {
			hi = *recx;
			end_hi = end;
		}
		if (end < end_lo) {
			lo = *recx;
			end_lo = end;
		}
		D_ASSERT(end_hi >= end_lo);
	}

out:
	*hi_ptr = hi;
	*lo_ptr = lo;
}

static inline void
daos_recx_ep_list_dump(struct daos_recx_ep_list *lists, unsigned int nr)
{
	struct daos_recx_ep_list	*list;
	struct daos_recx_ep		*recx_ep;
	unsigned int			 i, j;

	if (lists == NULL || nr == 0) {
		D_ERROR("empty daos_recx_ep_list.\n");
		return;
	}
	for (i = 0; i < nr; i++) {
		list = &lists[i];
		D_ERROR("daos_recx_ep_list[%d], nr %d, total %d, "
			"re_ep_valid %d, re_snapshot %d:\n",
			i, list->re_nr, list->re_total, list->re_ep_valid,
			list->re_snapshot);
		for (j = 0; j < list->re_nr; j++) {
			recx_ep = &list->re_items[j];
			D_ERROR("[["DF_X64","DF_X64"], "DF_X64"]  ",
				recx_ep->re_recx.rx_idx, recx_ep->re_recx.rx_nr,
				recx_ep->re_ep);
		}
		D_ERROR("\n");
	}
}

extern daos_metrics_cntr_t   *obj_rpc_cntrs;

static inline int
dc_obj_metrics_incr_inflightcntr(int opc) {
        if (obj_rpc_cntrs) {
                return dc_metrics_incr_inflightcntr(&obj_rpc_cntrs[opc_get(opc)]);
        }
        return 0;
}

static inline int
dc_obj_metrics_incr_completecntr(int opc, int rc) {
        if (obj_rpc_cntrs) {
                return dc_metrics_incr_completecntr(&obj_rpc_cntrs[opc_get(opc)], rc);
        }
        return 0;
}

int dc_obj_metrics_init();
void dc_obj_metrics_fini();
int dc_obj_metrics_get_rpccntrs(daos_metrics_obj_rpc_cntrs_t *cntrs);
int dc_obj_metrics_reset();
#endif /* __DD_OBJ_H__ */

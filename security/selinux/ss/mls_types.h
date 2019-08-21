/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Type definitions for the multi-level security (MLS) policy.
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */
/*
 * Updated: Trusted Computer Solutions, Inc. <dgoeddel@trustedcs.com>
 *
 *	Support for enhanced MLS infrastructure.
 *
 * Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 */

#ifndef _SS_MLS_TYPES_H_
#define _SS_MLS_TYPES_H_

#include "security.h"
#include "ebitmap.h"

struct mls_level {
	u32 sens;		/* sensitivity */
	struct ebitmap cat;	/* category set */
};

struct mls_range {
	struct mls_level level[2]; /* low == level[0], high == level[1] */
};

static inline int mls_level_eq(struct mls_level *l1, struct mls_level *l2)
{
	return ((l1->sens == l2->sens) &&
		ebitmap_cmp(&l1->cat, &l2->cat));
}

static inline int mls_level_dom(struct mls_level *l1, struct mls_level *l2)
{
	return ((l1->sens >= l2->sens) &&
		ebitmap_contains(&l1->cat, &l2->cat, 0));
}

static inline int mls_range_glblub(struct mls_range *dst, struct mls_range *r1, struct mls_range *r2)
{
	int rc = 0;

	if ((r1->level[0].sens < r2->level[1].sens && r2->level[0].sens > r1->level[1].sens) ||
	    (r1->level[0].sens > r2->level[1].sens && r2->level[0].sens < r1->level[1].sens))
	{
		// These ranges have no common sensitivities
		return -1;
	}

	// Take the greatest of the low
	dst->level[0].sens = max(r1->level[0].sens, r2->level[0].sens);

        // Take the least of the high
	dst->level[1].sens = min(r1->level[1].sens, r2->level[1].sens);

	rc = ebitmap_and(&dst->level[0].cat, &r1->level[0].cat, &r2->level[0].cat);
	if (rc)
		goto out;

	rc = ebitmap_and(&dst->level[1].cat, &r1->level[1].cat, &r2->level[1].cat);
	if (rc)
		goto out;

out:
	return rc;
}

#define mls_level_incomp(l1, l2) \
(!mls_level_dom((l1), (l2)) && !mls_level_dom((l2), (l1)))

#define mls_level_between(l1, l2, l3) \
(mls_level_dom((l1), (l2)) && mls_level_dom((l3), (l1)))

#define mls_range_contains(r1, r2) \
(mls_level_dom(&(r2).level[0], &(r1).level[0]) && \
 mls_level_dom(&(r1).level[1], &(r2).level[1]))

#endif	/* _SS_MLS_TYPES_H_ */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XT_TRIPSO_H
#define _XT_TRIPSO_H

enum {
	TRIPSO_CIPSO = 1,
	TRIPSO_ASTRA
};

struct tripso_info {
	uint32_t tr_mode;
};

#endif /* _XT_TRIPSO_H */

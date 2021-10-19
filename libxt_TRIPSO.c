/*
 * xtables helper library for netfilter module which translates between CIPSO
 * and GOST R 58256-2018 (RFC 1108 Astra) security labels.
 *
 * Copyright (C) 2018-2021 vt@altlinux.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xtables.h>
#include <netinet/ether.h>
#include "xt_TRIPSO.h"

enum {
	O_TRIPSO_CIPSO = 0,
	O_TRIPSO_ASTRA,
};

static const struct xt_option_entry tripso_tg_opts[] = {
	{.name = "to-cipso", .id = O_TRIPSO_CIPSO, .type = XTTYPE_NONE,
		.excl = O_TRIPSO_ASTRA,},
	{.name = "to-astra", .id = O_TRIPSO_ASTRA, .type = XTTYPE_NONE,
		.excl = O_TRIPSO_CIPSO,},
	XTOPT_TABLEEND
};

static void tripso_tg_help(void)
{
	printf(
"TRIPSO target options:\n"
"  --to-cipso                    Set TRIPSO translation mode\n"
"  --to-astra                    Set TRIPSO translation mode\n"
	);
}

static void tripso_tg_parse(struct xt_option_call *cb)

{
	struct tripso_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TRIPSO_CIPSO:
		info->tr_mode = TRIPSO_CIPSO;
		break;
	case O_TRIPSO_ASTRA:
		info->tr_mode = TRIPSO_ASTRA;
	}
}

static void tripso_tg_init(struct xt_entry_target *target)
{
	struct tripso_info *info = (void *)target->data;

	info->tr_mode = -1; /* should be changed */
}

static void tripso_tg_check(struct xt_fcheck_call *cb)
{
	struct tripso_info *info = cb->data;

	if (info->tr_mode == -1)
		xtables_error(PARAMETER_PROBLEM,
		    "TRIPSO target: --to-cipso or --to-astra parameter required");
}

static void tripso_tg_save(const void *ip,
    const struct xt_entry_target *target)
{
	const struct tripso_info *info = (const void *)target->data;

	printf(" --to-%s ", info->tr_mode == TRIPSO_CIPSO? "cipso" :
	    info->tr_mode == TRIPSO_ASTRA? "astra" : "error");
}

static void tripso_tg_print(const void *ip,
    const struct xt_entry_target *target, int numeric)
{
	printf(" -j TRIPSO");
	tripso_tg_save(ip, target);
}

static struct xtables_target tripso_tg_reg = {
	.version	= XTABLES_VERSION,
	.name		= "TRIPSO",
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct tripso_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct tripso_info)),
	.help		= tripso_tg_help,
	.init		= tripso_tg_init,
	.print		= tripso_tg_print,
	.save		= tripso_tg_save,
	.x6_parse	= tripso_tg_parse,
	.x6_fcheck	= tripso_tg_check,
	.x6_options	= tripso_tg_opts,
};

static __attribute__((constructor)) void tripso_tg_ldr(void)
{
	xtables_register_target(&tripso_tg_reg);
}


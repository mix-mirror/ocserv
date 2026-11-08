/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CONFIG_COPY_H
#define CONFIG_COPY_H

#include "cfg.pb-c.h"

/* A deep copy of @def, allocated under @pool, with every list option left
 * empty: what a named vhost starts from before its section is parsed
 * (REQ-CONFIG-CFG-002). Returns NULL on memory failure. */
ReloadableConfig *cfg_copy_without_lists(const ReloadableConfig *def,
					 void *pool);

/* Gives @cfg, at any depth, every list option of @def that @cfg left empty:
 * the lists a named vhost did not set, taken from the default vhost
 * (REQ-CONFIG-CFG-010). @cfg is modified and, on success, freed and replaced
 * by the returned deep copy allocated under @pool. Returns NULL on memory
 * failure, leaving @cfg allocated. */
ReloadableConfig *cfg_inherit_lists(ReloadableConfig *cfg,
				    const ReloadableConfig *def, void *pool);

#endif /* CONFIG_COPY_H */

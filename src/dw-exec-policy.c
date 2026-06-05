#define _GNU_SOURCE

#include <pthread.h>
#include <stdbool.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libpatch/patch.h>

#include "dw-exec-policy.h"
#include "dw-log.h"

#define MAIN_OBJ_MAX_EXEC_SEGS 32
#define DW_EXEC_MAPPING_MAX_REGIONS 512
#define DW_EXEC_MAPPING_LINE_MAX 4096
#define DW_EXEC_MAPPING_PATH_MAX 2048

struct dw_exec_region {
	uintptr_t start;
	uintptr_t end;
};

enum dw_exec_mapping_kind {
	DW_EXEC_MAP_FILE_BACKED = 0,
	DW_EXEC_MAP_OTHER,
};

struct dw_exec_mapping {
	uintptr_t start;
	uintptr_t end;
	enum dw_exec_mapping_kind kind;
};

static struct dw_exec_region main_obj_exec_segs[MAIN_OBJ_MAX_EXEC_SEGS];
static size_t main_obj_exec_seg_count = 0;
static bool main_obj_range_ready = false;
static struct dw_exec_mapping exec_mappings[DW_EXEC_MAPPING_MAX_REGIONS];
static size_t exec_mapping_count = 0;
static __thread int exec_mapping_last_idx = -1;
/*
 * Serializes lookups against the /proc/self/maps rebuild: the refresh resets
 * exec_mapping_count and rewrites exec_mappings[] in place, so concurrent
 * faulting threads would otherwise read a torn cache. Only taken on the cold
 * instruction-entry creation path (trampoline context, never in a signal
 * handler).
 */
static pthread_mutex_t exec_mapping_mu = PTHREAD_MUTEX_INITIALIZER;

static void add_main_object_exec_seg(uintptr_t start, uintptr_t end)
{
	if (start == 0 || end <= start)
		return;

	for (size_t i = 0; i < main_obj_exec_seg_count; i++) {
		struct dw_exec_region *region = &main_obj_exec_segs[i];
		if (end <= region->start || start >= region->end)
			continue;

		if (start < region->start)
			region->start = start;
		if (end > region->end)
			region->end = end;
		return;
	}

	if (main_obj_exec_seg_count >= MAIN_OBJ_MAX_EXEC_SEGS)
		return;

	main_obj_exec_segs[main_obj_exec_seg_count++] =
		(struct dw_exec_region){.start = start, .end = end};
}

static bool load_main_object_exec_segments(const struct dl_phdr_info *info)
{
	for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];

		if (phdr->p_type != PT_LOAD)
			continue;
		if ((phdr->p_flags & PF_X) == 0)
			continue;
		if (phdr->p_memsz == 0)
			continue;

		add_main_object_exec_seg((uintptr_t)info->dlpi_addr + (uintptr_t)phdr->p_vaddr,
						 (uintptr_t)info->dlpi_addr + (uintptr_t)phdr->p_vaddr +
							 (uintptr_t)phdr->p_memsz);
	}

	return main_obj_exec_seg_count > 0;
}

static int find_main_object_range_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	(void)size;
	(void)data;

	/* For the main executable, glibc typically provides an empty dlpi_name. */
	if (info->dlpi_name && info->dlpi_name[0] != '\0')
		return 0;

	if (load_main_object_exec_segments(info))
		main_obj_range_ready = true;

	/* Stop after finding the main program. */
	return 1;
}

void init_main_object_range(void)
{
	if (main_obj_range_ready)
		return;

	main_obj_exec_seg_count = 0;
	dl_iterate_phdr(find_main_object_range_cb, NULL);
}

bool dw_main_object_range_available(void)
{
	if (!main_obj_range_ready)
		init_main_object_range();

	return main_obj_range_ready;
}

bool dw_addr_in_main_object(uintptr_t addr)
{
	if (!dw_main_object_range_available())
		return false;

	for (size_t i = 0; i < main_obj_exec_seg_count; i++) {
		if (addr >= main_obj_exec_segs[i].start && addr < main_obj_exec_segs[i].end)
			return true;
	}

	return false;
}

static enum dw_exec_mapping_kind classify_exec_mapping_path(const char *path)
{
	if (path != NULL && path[0] == '/')
		return DW_EXEC_MAP_FILE_BACKED;

	return DW_EXEC_MAP_OTHER;
}

static bool find_olx_original_pc(uintptr_t addr, uintptr_t *patch_insn_out)
{
	uintptr_t patch_insn = 0;

	if (patch_olx_original_pc(addr, &patch_insn) != PATCH_OK || patch_insn == 0)
		return false;

	if (patch_insn_out)
		*patch_insn_out = patch_insn;
	return true;
}

static void add_exec_mapping(uintptr_t start, uintptr_t end, enum dw_exec_mapping_kind kind)
{
	if (start == 0 || end <= start)
		return;

	if (exec_mapping_count > 0) {
		struct dw_exec_mapping *prev = &exec_mappings[exec_mapping_count - 1];
		if (prev->kind == kind && start <= prev->end) {
			if (end > prev->end)
				prev->end = end;
			return;
		}
	}

	if (exec_mapping_count >= DW_EXEC_MAPPING_MAX_REGIONS) {
		DW_LOG(WARNING, MAIN,
			   "Executable mapping cache capacity reached; some regions were ignored.\n");
		return;
	}

	exec_mappings[exec_mapping_count++] =
		(struct dw_exec_mapping){.start = start, .end = end, .kind = kind};
}

/* Caller must hold exec_mapping_mu. */
static void refresh_exec_mapping_cache_locked(void)
{
	FILE *maps;
	char line[DW_EXEC_MAPPING_LINE_MAX];

	exec_mapping_count = 0;
	exec_mapping_last_idx = -1;

	maps = fopen("/proc/self/maps", "r");
	if (maps == NULL) {
		DW_LOG(WARNING, MAIN, "Unable to open /proc/self/maps for executable classification.\n");
		return;
	}

	while (fgets(line, sizeof(line), maps) != NULL) {
		unsigned long start_raw, end_raw;
		char perms[5];
		char path[DW_EXEC_MAPPING_PATH_MAX];
		char *trimmed;
		int fields;

		start_raw = 0;
		end_raw = 0;
		perms[0] = '\0';
		path[0] = '\0';

		fields = sscanf(line, "%lx-%lx %4s %*s %*s %*s %2047[^\n]",
						&start_raw, &end_raw, perms, path);
		if (fields < 3)
			continue;
		if (strchr(perms, 'x') == NULL)
			continue;

		trimmed = path;
		if (fields >= 4) {
			while (*trimmed == ' ' || *trimmed == '\t')
				trimmed++;
		} else {
			trimmed = "";
		}

		add_exec_mapping((uintptr_t)start_raw, (uintptr_t)end_raw,
					 classify_exec_mapping_path(trimmed));
	}

	fclose(maps);
}

/* Caller must hold exec_mapping_mu. */
static const struct dw_exec_mapping *find_exec_mapping_locked(uintptr_t addr)
{
	/*
	 * The hint may predate a rebuild that shrank the cache, so it is only
	 * trusted when it still points at a live entry.
	 */
	if (exec_mapping_last_idx >= 0 && (size_t)exec_mapping_last_idx < exec_mapping_count) {
		const struct dw_exec_mapping *mapping = &exec_mappings[exec_mapping_last_idx];
		if (addr >= mapping->start && addr < mapping->end)
			return mapping;
	}

	for (size_t i = 0; i < exec_mapping_count; i++) {
		const struct dw_exec_mapping *mapping = &exec_mappings[i];
		if (addr < mapping->start)
			break;
		if (addr >= mapping->start && addr < mapping->end) {
			exec_mapping_last_idx = (int)i;
			return mapping;
		}
	}

	return NULL;
}

/*
 * Thread-safe lookup. The kind is copied out under the lock because a
 * concurrent refresh rewrites the array slots in place, so a returned
 * pointer would not be safe to dereference after unlocking. When
 * refresh_first is set, the cache is rebuilt from /proc/self/maps before
 * the lookup (both under the same critical section).
 */
static bool find_exec_mapping_kind(uintptr_t addr, bool refresh_first,
				   enum dw_exec_mapping_kind *kind_out)
{
	const struct dw_exec_mapping *mapping;
	bool found = false;

	(void)pthread_mutex_lock(&exec_mapping_mu);
	if (refresh_first)
		refresh_exec_mapping_cache_locked();
	mapping = find_exec_mapping_locked(addr);
	if (mapping != NULL) {
		*kind_out = mapping->kind;
		found = true;
	}
	(void)pthread_mutex_unlock(&exec_mapping_mu);

	return found;
}

void dw_exec_policy_init(void)
{
	init_main_object_range();
	(void)pthread_mutex_lock(&exec_mapping_mu);
	refresh_exec_mapping_cache_locked();
	(void)pthread_mutex_unlock(&exec_mapping_mu);
}

bool dw_patch_disabled_for_addr(uintptr_t addr, uintptr_t *patch_insn_out)
{
	enum dw_exec_mapping_kind kind = DW_EXEC_MAP_OTHER;
	bool found;

	if (patch_insn_out)
		*patch_insn_out = 0;

	if (dw_addr_in_main_object(addr))
		return false;

	found = find_exec_mapping_kind(addr, false, &kind);
	if (found && kind == DW_EXEC_MAP_FILE_BACKED)
		return false;

	/*
	 * libpatch may create OLX mappings after the /proc/self/maps cache was
	 * built.  Ask libpatch directly before forcing a cache refresh.
	 */
	if (find_olx_original_pc(addr, patch_insn_out))
		return false;

	if (!found)
		found = find_exec_mapping_kind(addr, true, &kind);

	if (!found)
		return true;

	return kind != DW_EXEC_MAP_FILE_BACKED;
}

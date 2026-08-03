// SPDX-License-Identifier: MIT
#include <linux/init.h>
#include <linux/module.h>
#include <linux/stddef.h>

#define ARACH_MODULE_ABI_MAGIC 0x49424148U
#define ARACH_MODULE_ABI_VERSION 1U
#define ARACH_MODULE_ABI_ABSENT (~0U)

#ifdef CONFIG_MODULE_UNLOAD
#define ARACH_MODULE_EXIT_OFFSET ((u32)offsetof(struct module, exit))
#define ARACH_MODULE_REFCNT_OFFSET ((u32)offsetof(struct module, refcnt))
#else
#define ARACH_MODULE_EXIT_OFFSET ARACH_MODULE_ABI_ABSENT
#define ARACH_MODULE_REFCNT_OFFSET ARACH_MODULE_ABI_ABSENT
#endif

#ifdef ARACH_MODULE_MEMORY_HAS_ROX
#define ARACH_MODULE_MEMORY_ROX_OFFSET \
    ((u32)offsetof(struct module_memory, is_rox))
#else
#define ARACH_MODULE_MEMORY_ROX_OFFSET ARACH_MODULE_ABI_ABSENT
#endif

/*
 * Kbuild emits this non-semantic measurement alongside the smoke module. It
 * captures the exact configured/randstruct layout used by this SDK; Arach
 * never infers these offsets from a different running kernel.
 */
struct arach_module_abi_v1 {
    u32 magic;
    u32 version;
    u32 record_size;
    u32 module_size;
    u32 module_alignment;
    u32 module_name_length;
    u32 state_offset;
    u32 list_offset;
    u32 name_offset;
    u32 init_offset;
    u32 memory_offset;
    u32 memory_count;
    u32 memory_stride;
    u32 memory_base_offset;
    u32 memory_rox_offset;
    u32 memory_size_offset;
    u32 arch_offset;
    u32 exit_offset;
    u32 refcnt_offset;
} __packed;

static const struct arach_module_abi_v1 arach_module_abi
    __used __section(".arach.module_abi") = {
        .magic = ARACH_MODULE_ABI_MAGIC,
        .version = ARACH_MODULE_ABI_VERSION,
        .record_size = sizeof(struct arach_module_abi_v1),
        .module_size = sizeof(struct module),
        .module_alignment = __alignof__(struct module),
        .module_name_length = MODULE_NAME_LEN,
        .state_offset = offsetof(struct module, state),
        .list_offset = offsetof(struct module, list),
        .name_offset = offsetof(struct module, name),
        .init_offset = offsetof(struct module, init),
        .memory_offset = offsetof(struct module, mem),
        .memory_count = MOD_MEM_NUM_TYPES,
        .memory_stride = sizeof(struct module_memory),
        .memory_base_offset = offsetof(struct module_memory, base),
        .memory_rox_offset = ARACH_MODULE_MEMORY_ROX_OFFSET,
        .memory_size_offset = offsetof(struct module_memory, size),
        .arch_offset = offsetof(struct module, arch),
        .exit_offset = ARACH_MODULE_EXIT_OFFSET,
        .refcnt_offset = ARACH_MODULE_REFCNT_OFFSET,
};

static int __init arach_contract_smoke_init(void)
{
    pr_info("arach Linux contract smoke module initialized\n");
    return 0;
}

static void __exit arach_contract_smoke_exit(void)
{
    pr_info("arach Linux contract smoke module removed\n");
}

module_init(arach_contract_smoke_init);
module_exit(arach_contract_smoke_exit);

MODULE_DESCRIPTION("Arach external Kbuild contract smoke module");
MODULE_AUTHOR("ArachOS");
MODULE_LICENSE("MIT");

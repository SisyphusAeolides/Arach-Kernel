// SPDX-License-Identifier: MIT
#include <linux/init.h>
#include <linux/module.h>

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
MODULE_AUTHOR("Arach OS");
MODULE_LICENSE("MIT");

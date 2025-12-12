#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/smp.h>

#ifdef CONFIG_X86
#include <asm/msr.h>
#endif

#define MSR_IA32_THERM_STATUS 0x19c

MODULE_LICENSE("GPL");
MODULE_AUTHOR("energy-aware-scx");
MODULE_DESCRIPTION("BPF kfunc for reading IA32_THERM_STATUS");

static __bpf_kfunc u64 therm_read_ia32_therm_status(void)
{
#ifdef CONFIG_X86
	u64 val = 0;

	rdmsrl(MSR_IA32_THERM_STATUS, val);
	return val;
#else
	return 0;
#endif
}

BTF_SET_START(therm_kfunc_ids)
BTF_ID(func, therm_read_ia32_therm_status)
BTF_SET_END(therm_kfunc_ids)

static const struct btf_kfunc_id_set therm_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &therm_kfunc_ids,
};

static int __init therm_kfunc_init(void)
{
	return register_btf_kfunc_id_set(&therm_kfunc_set);
}

static void __exit therm_kfunc_exit(void)
{
	unregister_btf_kfunc_id_set(&therm_kfunc_set);
}

module_init(therm_kfunc_init);
module_exit(therm_kfunc_exit);

// SPDX-License-Identifier: GPL-2.0-only

/*
 * Setup Key Locker feature and support the wrapping key management.
 */

#include <linux/random.h>
#include <linux/string.h>

#include <asm/fpu/api.h>
#include <asm/keylocker.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>

static struct iwkey wrapping_key __initdata;

static void __init generate_keylocker_data(void)
{
	get_random_bytes(&wrapping_key.integrity_key, sizeof(wrapping_key.integrity_key));
	get_random_bytes(&wrapping_key.encryption_key, sizeof(wrapping_key.encryption_key));
}

static void __init destroy_keylocker_data(void)
{
	memzero_explicit(&wrapping_key, sizeof(wrapping_key));
}

/*
 * For loading the wrapping key into each CPU, the feature bit is set
 * in the control register and FPU context management is performed.
 */
static void __init load_keylocker(struct work_struct *unused)
{
	cr4_set_bits(X86_CR4_KEYLOCKER);

	kernel_fpu_begin();
	load_xmm_iwkey(&wrapping_key);
	kernel_fpu_end();
}

static int __init init_keylocker(void)
{
	u32 eax, ebx, ecx, edx;

	if (!cpu_feature_enabled(X86_FEATURE_KEYLOCKER))
		goto disable;

	if (cpu_feature_enabled(X86_FEATURE_HYPERVISOR)) {
		pr_debug("x86/keylocker: Not compatible with a hypervisor.\n");
		goto clear_cap;
	}

	cr4_set_bits(X86_CR4_KEYLOCKER);

	/* AESKLE depends on CR4.KEYLOCKER */
	cpuid_count(KEYLOCKER_CPUID, 0, &eax, &ebx, &ecx, &edx);
	if (!(ebx & KEYLOCKER_CPUID_EBX_AESKLE) ||
	    !(eax & KEYLOCKER_CPUID_EAX_SUPERVISOR)) {
		pr_debug("x86/keylocker: Not fully supported.\n");
		goto clear_cap;
	}

	generate_keylocker_data();
	schedule_on_each_cpu(load_keylocker);
	destroy_keylocker_data();

	pr_info_once("x86/keylocker: Enabled.\n");
	return 0;

clear_cap:
	setup_clear_cpu_cap(X86_FEATURE_KEYLOCKER);
	pr_info_once("x86/keylocker: Disabled.\n");
disable:
	cr4_clear_bits(X86_CR4_KEYLOCKER);
	return -ENODEV;
}

arch_initcall(init_keylocker);

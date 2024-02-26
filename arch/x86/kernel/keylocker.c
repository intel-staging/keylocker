// SPDX-License-Identifier: GPL-2.0-only

/*
 * Setup Key Locker feature and support the wrapping key management.
 */

#include <linux/random.h>
#include <linux/string.h>

#include <asm/fpu/api.h>
#include <asm/keylocker.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>

static struct iwkey wrapping_key __initdata;

/*
 * This flag is set when a wrapping key is successfully loaded. If a key
 * restoration fails, it is reset. This state is exported to the crypto
 * library, indicating whether Key Locker is usable. Thus, the feature
 * can be soft-disabled based on this flag.
 */
static bool valid_wrapping_key;

bool valid_keylocker(void)
{
	return valid_wrapping_key;
}
EXPORT_SYMBOL_GPL(valid_keylocker);

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

/**
 * copy_keylocker - Copy the wrapping key from the backup.
 *
 * Returns:	true if successful, otherwise false.
 */
static bool copy_keylocker(void)
{
	u64 status;

	wrmsrl(MSR_IA32_COPY_IWKEY_TO_LOCAL, 1);
	rdmsrl(MSR_IA32_IWKEY_COPY_STATUS, status);
	return !!(status & BIT(0));
}

/*
 * On wakeup, APs copy a wrapping key after the boot CPU verifies a valid
 * backup status through restore_keylocker(). Subsequently, they adhere
 * to the error handling protocol by invalidating the flag.
 *
 * This setup routine is also invoked in the hotplug bringup path.
 */
void setup_keylocker(void)
{
	if (!valid_wrapping_key)
		return;

	cr4_set_bits(X86_CR4_KEYLOCKER);

	if (copy_keylocker())
		return;

	pr_err_once("x86/keylocker: Invalid copy status.\n");
	valid_wrapping_key = false;
}

/* The boot CPU restores the wrapping key in the first place on wakeup. */
void restore_keylocker(void)
{
	u64 backup_status;

	if (!valid_wrapping_key)
		return;

	rdmsrl(MSR_IA32_IWKEY_BACKUP_STATUS, backup_status);
	if (backup_status & BIT(0)) {
		if (copy_keylocker())
			return;
		pr_err("x86/keylocker: Invalid copy state.\n");
	} else {
		pr_err("x86/keylocker: The key backup access failed with %s.\n",
		       (backup_status & BIT(2)) ? "read error" : "invalid status");
	}

	/*
	 * Invalidate the feature via this flag to indicate that the
	 * crypto code should voluntarily stop using the feature, rather
	 * than abruptly disabling it.
	 */
	valid_wrapping_key = false;
}

/* Check if Key Locker is secure enough to be used. */
static bool __init secure_keylocker(void)
{
	if (boot_cpu_has_bug(X86_BUG_GDS) && !gds_ucode_mitigated(MITG_LOCKED))
		return false;

	if (boot_cpu_has_bug(X86_BUG_RFDS) && rfds_mitigation != RFDS_MITIGATION_VERW)
		return false;

	return true;
}

static int __init init_keylocker(void)
{
	u32 eax, ebx, ecx, edx;
	bool backup_available;

	if (!cpu_feature_enabled(X86_FEATURE_KEYLOCKER))
		goto disable;

	if (cpu_feature_enabled(X86_FEATURE_HYPERVISOR)) {
		pr_debug("x86/keylocker: Not compatible with a hypervisor.\n");
		goto clear_cap;
	}

	if (!secure_keylocker())
		goto clear_cap;

	cr4_set_bits(X86_CR4_KEYLOCKER);

	/* AESKLE depends on CR4.KEYLOCKER */
	cpuid_count(KEYLOCKER_CPUID, 0, &eax, &ebx, &ecx, &edx);
	if (!(ebx & KEYLOCKER_CPUID_EBX_AESKLE) ||
	    !(eax & KEYLOCKER_CPUID_EAX_SUPERVISOR)) {
		pr_debug("x86/keylocker: Not fully supported.\n");
		goto clear_cap;
	}

	/*
	 * The backup is critical for restoring the wrapping key upon
	 * wakeup or during hotplug bringup.
	 */
	backup_available = !!(ebx & KEYLOCKER_CPUID_EBX_BACKUP);
	if (!backup_available && (IS_ENABLED(CONFIG_SUSPEND) || IS_ENABLED(CONFIG_HOTPLUG_CPU))) {
		pr_debug("x86/keylocker: No key backup with possible S3/4 or CPU hotplug.\n");
		goto clear_cap;
	}

	generate_keylocker_data();
	schedule_on_each_cpu(load_keylocker);
	destroy_keylocker_data();
	valid_wrapping_key = true;

	if (backup_available)
		wrmsrl(MSR_IA32_BACKUP_IWKEY_TO_PLATFORM, 1);

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

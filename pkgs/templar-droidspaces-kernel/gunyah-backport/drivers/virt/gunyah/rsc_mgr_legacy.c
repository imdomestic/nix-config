// SPDX-License-Identifier: GPL-2.0-only
/*
 * Adapter between the upstream Gunyah host-VM ABI and Qualcomm's legacy
 * Android 5.10 gh_rm_drv transport.
 *
 * The downstream RM driver is already used by display, haptics, QRTR and
 * several other vendor modules.  This adapter deliberately reuses that
 * driver's RPC transport and notification chain instead of binding a second
 * driver to the resource-manager DT node.
 */

#define pr_fmt(fmt) "gunyah_legacy_rm: " fmt

#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/slab.h>

#include <linux/gunyah.h>
#include <linux/gunyah_rsc_mgr.h>

#include "rsc_mgr.h"
#include "vm_mgr.h"

typedef void *(*legacy_rm_call_fn_t)(u32 message_id, void *req_buf,
				     size_t req_buf_size, size_t *resp_buf_size,
				     int *reply_error);
typedef int (*legacy_rm_notifier_fn_t)(struct notifier_block *nb);
typedef int (*legacy_rm_virq_to_irq_fn_t)(u32 virq, u32 type);
typedef int (*legacy_rm_get_vmid_fn_t)(int vm_name, u16 *vmid);
typedef int (*legacy_hyp_assign_phys_fn_t)(phys_addr_t addr, u64 size,
					   u32 *source_vmids,
					   int source_count,
					   int *dest_vmids,
					   int *dest_perms,
					   int dest_count);

struct gh_rm {
	struct miscdevice miscdev;
};

static struct gh_rm legacy_rm;
static legacy_rm_call_fn_t legacy_rm_call;
static legacy_rm_notifier_fn_t legacy_rm_register_notifier;
static legacy_rm_notifier_fn_t legacy_rm_unregister_notifier;
static legacy_rm_virq_to_irq_fn_t legacy_rm_virq_to_irq;
static legacy_rm_get_vmid_fn_t legacy_rm_get_vmid;
static legacy_hyp_assign_phys_fn_t legacy_hyp_assign_phys;

static unsigned long ghh_lookup_symbol(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name,
	};
	unsigned long addr;
	int ret;

	ret = register_kprobe(&kp);
	if (ret)
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

/* The legacy module was built with Clang CFI.  These addresses are resolved
 * from kprobes rather than through module relocations, so suppress CFI at the
 * one carefully typed indirect-call boundary.
 */
static __nocfi void *ghh_legacy_call(u32 message_id, void *req_buf,
				     size_t req_buf_size, size_t *resp_buf_size,
				     int *reply_error)
{
	return legacy_rm_call(message_id, req_buf, req_buf_size,
			      resp_buf_size, reply_error);
}

static __nocfi int ghh_legacy_notifier_call(legacy_rm_notifier_fn_t fn,
					    struct notifier_block *nb)
{
	return fn(nb);
}

static __nocfi int ghh_legacy_virq_to_irq(u32 virq, u32 type)
{
	return legacy_rm_virq_to_irq(virq, type);
}

static __nocfi int ghh_legacy_get_vmid(int vm_name, u16 *vmid)
{
	return legacy_rm_get_vmid(vm_name, vmid);
}

static __nocfi int ghh_legacy_assign_mem(phys_addr_t mem_addr, u64 mem_size,
					 u32 *source_vmids, int source_count,
					 int *dest_vmids, int *dest_perms,
					 int dest_count)
{
	return legacy_hyp_assign_phys(mem_addr, mem_size, source_vmids,
				      source_count, dest_vmids, dest_perms,
				      dest_count);
}

#define GH_SCM_VMID_HLOS 0x3
#define GH_SCM_PERM_EXEC 0x1
#define GH_SCM_PERM_WRITE 0x2
#define GH_SCM_PERM_READ 0x4
#define GH_SCM_PERM_RWX (GH_SCM_PERM_READ | GH_SCM_PERM_WRITE | GH_SCM_PERM_EXEC)

/* enum gh_vm_names in Qualcomm's legacy ABI: SELF=0, PRIMARY=1. */
#define GH_LEGACY_PRIMARY_VM 1

int ghh_rm_platform_get_vmid(struct gh_rm *rm, u16 *vmid)
{
	if (rm != &legacy_rm || !vmid)
		return -EINVAL;

	return ghh_legacy_get_vmid(GH_LEGACY_PRIMARY_VM, vmid);
}

int ghh_rm_platform_pre_mem_share(struct gh_rm *rm,
					  struct ghh_rm_mem_parcel *parcel)
{
	u32 source_vmid = GH_SCM_VMID_HLOS;
	u32 *rollback_vmids;
	int *dest_vmids, *dest_perms;
	u16 vmid;
	int i, n, ret = 0;

	dest_vmids = kcalloc(parcel->n_acl_entries, sizeof(*dest_vmids), GFP_KERNEL);
	dest_perms = kcalloc(parcel->n_acl_entries, sizeof(*dest_perms), GFP_KERNEL);
	rollback_vmids = kcalloc(parcel->n_acl_entries, sizeof(*rollback_vmids), GFP_KERNEL);
	if (!dest_vmids || !dest_perms || !rollback_vmids) {
		ret = -ENOMEM;
		goto out;
	}

	if (rm != &legacy_rm) {
		ret = -EINVAL;
		goto out;
	}

	for (n = 0; n < parcel->n_acl_entries; n++) {
		vmid = le16_to_cpu(parcel->acl_entries[n].vmid);
		/* The legacy Qualcomm driver passes the VMID allocated by RM
		 * directly to hyp_assign_phys(). Keep that exact contract here.
		 */
		dest_vmids[n] = vmid;
		rollback_vmids[n] = dest_vmids[n];
		if (parcel->acl_entries[n].perms & GH_RM_ACL_X)
			dest_perms[n] |= GH_SCM_PERM_EXEC;
		if (parcel->acl_entries[n].perms & GH_RM_ACL_W)
			dest_perms[n] |= GH_SCM_PERM_WRITE;
		if (parcel->acl_entries[n].perms & GH_RM_ACL_R)
			dest_perms[n] |= GH_SCM_PERM_READ;
	}

	for (i = 0; i < parcel->n_mem_entries; i++) {
		ret = ghh_legacy_assign_mem(
			le64_to_cpu(parcel->mem_entries[i].phys_addr),
			le64_to_cpu(parcel->mem_entries[i].size), &source_vmid, 1,
			dest_vmids, dest_perms, parcel->n_acl_entries);
		if (ret)
			break;
	}

	if (!ret)
		goto out;

	dest_vmids[0] = GH_SCM_VMID_HLOS;
	dest_perms[0] = GH_SCM_PERM_RWX;
	for (i--; i >= 0; i--)
		WARN_ON_ONCE(ghh_legacy_assign_mem(
			le64_to_cpu(parcel->mem_entries[i].phys_addr),
			le64_to_cpu(parcel->mem_entries[i].size), rollback_vmids,
			parcel->n_acl_entries, dest_vmids, dest_perms, 1));
out:
	kfree(rollback_vmids);
	kfree(dest_perms);
	kfree(dest_vmids);
	return ret;
}

int ghh_rm_platform_post_mem_reclaim(struct gh_rm *rm,
					     struct ghh_rm_mem_parcel *parcel)
{
	u32 *source_vmids;
	int dest_vmid = GH_SCM_VMID_HLOS;
	int dest_perm = GH_SCM_PERM_RWX;
	u16 vmid;
	int i, n, ret = 0;

	if (rm != &legacy_rm)
		return -EINVAL;

	source_vmids = kcalloc(parcel->n_acl_entries, sizeof(*source_vmids), GFP_KERNEL);
	if (!source_vmids)
		return -ENOMEM;

	for (n = 0; n < parcel->n_acl_entries; n++) {
		vmid = le16_to_cpu(parcel->acl_entries[n].vmid);
		source_vmids[n] = vmid;
	}

	for (i = 0; i < parcel->n_mem_entries; i++) {
		ret = ghh_legacy_assign_mem(
			le64_to_cpu(parcel->mem_entries[i].phys_addr),
			le64_to_cpu(parcel->mem_entries[i].size), source_vmids,
			parcel->n_acl_entries, &dest_vmid, &dest_perm, 1);
		WARN_ON_ONCE(ret);
	}

	kfree(source_vmids);
	return ret;
}

static int ghh_rm_error_remap(u32 error)
{
	switch (error) {
	case 0:
		return 0;
	case 0xffffffff:
		return -EOPNOTSUPP;
	case 1:
		return -ENOMEM;
	case 2:
		return -ENODEV;
	case 3:
		return -EPERM;
	case 5:
		return -EBUSY;
	case 4:
	case 6 ... 0x11:
		return -EINVAL;
	default:
		return -EBADMSG;
	}
}

int ghh_rm_call(void *_rm, u32 message_id, const void *req_buf,
		size_t req_buf_size, void **resp_buf, size_t *resp_buf_size)
{
	u8 empty_request = 0;
	void *response;
	size_t response_size = 0;
	int reply_error = 0;

	if (_rm != &legacy_rm || !message_id || (!req_buf && req_buf_size))
		return -EINVAL;

	/* Qualcomm's 5.10 transport rejects a NULL request pointer even for
	 * zero-length RPCs. ACK legitimately uses NULL for those calls.
	 */
	if (!req_buf)
		req_buf = &empty_request;

	response = ghh_legacy_call(message_id, (void *)req_buf, req_buf_size,
				   &response_size, &reply_error);
	if (reply_error) {
		if (!IS_ERR_OR_NULL(response))
			kfree(response);
		return ghh_rm_error_remap(reply_error);
	}
	if (IS_ERR(response))
		return PTR_ERR(response);

	if (resp_buf_size)
		*resp_buf_size = response_size;
	if (response_size && resp_buf)
		*resp_buf = response;
	else
		kfree(response);

	return 0;
}

int ghh_rm_notifier_register(void *_rm, struct notifier_block *nb)
{
	if (_rm != &legacy_rm)
		return -EINVAL;
	return ghh_legacy_notifier_call(legacy_rm_register_notifier, nb);
}
EXPORT_SYMBOL_GPL(ghh_rm_notifier_register);

int ghh_rm_notifier_unregister(void *_rm, struct notifier_block *nb)
{
	if (_rm != &legacy_rm)
		return -EINVAL;
	return ghh_legacy_notifier_call(legacy_rm_unregister_notifier, nb);
}
EXPORT_SYMBOL_GPL(ghh_rm_notifier_unregister);

struct device *ghh_rm_get(struct gh_rm *rm)
{
	if (rm != &legacy_rm || !rm->miscdev.this_device)
		return NULL;
	return get_device(rm->miscdev.this_device);
}

void ghh_rm_put(struct gh_rm *rm)
{
	if (rm == &legacy_rm && rm->miscdev.this_device)
		put_device(rm->miscdev.this_device);
}

struct gh_resource *ghh_rm_alloc_resource(struct gh_rm *rm,
					   struct ghh_rm_hyp_resource *resource)
{
	struct gh_resource *ghrsc;
	u32 virq;
	int irq;

	if (rm != &legacy_rm)
		return NULL;

	ghrsc = kzalloc(sizeof(*ghrsc), GFP_KERNEL);
	if (!ghrsc)
		return NULL;

	ghrsc->type = resource->type;
	ghrsc->capid = le64_to_cpu(resource->cap_id);
	ghrsc->rm_label = le32_to_cpu(resource->resource_label);
	ghrsc->irq = IRQ_NOTCONNECTED;

	virq = le32_to_cpu(resource->virq);
	if (virq && virq != GH_RM_RESOURCE_NO_VIRQ) {
		irq = ghh_legacy_virq_to_irq(virq, IRQ_TYPE_EDGE_RISING);
		if (irq < 0) {
			pr_err("failed to map resource type %u label %u virq %u: %d\n",
			       ghrsc->type, ghrsc->rm_label, virq, irq);
			kfree(ghrsc);
			return NULL;
		}
		ghrsc->irq = irq;
	}

	return ghrsc;
}

void ghh_rm_free_resource(struct gh_resource *ghrsc)
{
	if (!ghrsc)
		return;
	if (ghrsc->irq != IRQ_NOTCONNECTED)
		irq_dispose_mapping(ghrsc->irq);
	kfree(ghrsc);
}

static long ghh_dev_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	return gh_dev_vm_mgr_ioctl(&legacy_rm, cmd, arg);
}

static const struct file_operations ghh_dev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ghh_dev_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = noop_llseek,
};

static int __init ghh_legacy_rm_init(void)
{
	legacy_rm_call = (legacy_rm_call_fn_t)ghh_lookup_symbol("gh_rm_call");
	legacy_rm_register_notifier = (legacy_rm_notifier_fn_t)
		ghh_lookup_symbol("gh_rm_register_notifier");
	legacy_rm_unregister_notifier = (legacy_rm_notifier_fn_t)
		ghh_lookup_symbol("gh_rm_unregister_notifier");
	legacy_rm_virq_to_irq = (legacy_rm_virq_to_irq_fn_t)
		ghh_lookup_symbol("gh_rm_virq_to_irq");
	legacy_rm_get_vmid = (legacy_rm_get_vmid_fn_t)
		ghh_lookup_symbol("gh_rm_get_vmid");
	legacy_hyp_assign_phys = (legacy_hyp_assign_phys_fn_t)
		ghh_lookup_symbol("hyp_assign_phys");

	if (!legacy_rm_call || !legacy_rm_register_notifier ||
	    !legacy_rm_unregister_notifier || !legacy_rm_virq_to_irq ||
	    !legacy_rm_get_vmid || !legacy_hyp_assign_phys) {
		pr_err("legacy gh_rm_drv symbols are unavailable\n");
		return -ENODEV;
	}

	legacy_rm.miscdev.name = "gunyah";
	legacy_rm.miscdev.minor = MISC_DYNAMIC_MINOR;
	legacy_rm.miscdev.fops = &ghh_dev_fops;

	return misc_register(&legacy_rm.miscdev);
}

static void __exit ghh_legacy_rm_exit(void)
{
	misc_deregister(&legacy_rm.miscdev);
}

module_init(ghh_legacy_rm_init);
module_exit(ghh_legacy_rm_exit);

MODULE_DESCRIPTION("Gunyah host VM manager over Qualcomm Android 5.10 legacy RM");
MODULE_LICENSE("GPL");

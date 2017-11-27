/*
 * Intel Software Guard Extensions support
 *
 * Copyright (c) 2017,  Intel Corporation
 *
 * Author: Kai Huang <kai.huang@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <asm/cpufeature.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <asm/sgx.h>
#include <xen/sched.h>
#include <asm/p2m.h>

struct sgx_cpuinfo __read_mostly boot_sgx_cpudata;

static bool __read_mostly opt_sgx_enabled = false;
boolean_param("sgx", opt_sgx_enabled);

#define total_epc_npages (boot_sgx_cpudata.epc_size >> PAGE_SHIFT)
#define epc_base_mfn (boot_sgx_cpudata.epc_base >> PAGE_SHIFT)
#define epc_base_maddr (boot_sgx_cpudata.epc_base)
#define epc_end_maddr (epc_base_maddr + boot_sgx_cpudata.epc_size)

static void *epc_base_vaddr = NULL;

static void *map_epc_page_to_xen(struct page_info *pg)
{
    BUG_ON(!epc_base_vaddr);

    return (void *)((unsigned long)epc_base_vaddr +
                    ((page_to_mfn(pg) - epc_base_mfn) << PAGE_SHIFT));
}

/* ENCLS opcode */
#define ENCLS   .byte 0x0f, 0x01, 0xcf

/*
 * ENCLS leaf functions
 *
 * However currently we only needs EREMOVE..
 */
enum {
    ECREATE = 0x0,
    EADD    = 0x1,
    EINIT   = 0x2,
    EREMOVE = 0x3,
    EDGBRD  = 0x4,
    EDGBWR  = 0x5,
    EEXTEND = 0x6,
    ELDU    = 0x8,
    EBLOCK  = 0x9,
    EPA     = 0xA,
    EWB     = 0xB,
    ETRACK  = 0xC,
    EAUG    = 0xD,
    EMODPR  = 0xE,
    EMODT   = 0xF,
};

/*
 * ENCLS error code
 *
 * Currently we only need SGX_CHILD_PRESENT
 */
#define SGX_CHILD_PRESENT   13

static inline int __encls(unsigned long rax, unsigned long rbx,
                          unsigned long rcx, unsigned long rdx)
{
    int ret;

    asm volatile ( "ENCLS;\n\t"
            : "=a" (ret)
            : "a" (rax), "b" (rbx), "c" (rcx), "d" (rdx)
            : "memory", "cc");

    return ret;
}

static inline int __eremove(void *epc)
{
    unsigned long rbx = 0, rdx = 0;

    return __encls(EREMOVE, rbx, (unsigned long)epc, rdx);
}

static int sgx_eremove(struct page_info *epg)
{
    void *addr = map_epc_page_to_xen(epg);
    int ret;

    BUG_ON(!addr);

    ret =  __eremove(addr);

    return ret;
}

struct sgx_domain *to_sgx(struct domain *d)
{
    if (!is_hvm_domain(d))
        return NULL;
    else
        return &d->arch.hvm_domain.vmx.sgx;
}

bool domain_epc_populated(struct domain *d)
{
    BUG_ON(!to_sgx(d));

    return !!to_sgx(d)->epc_base_pfn;
}

/*
 * Reset domain's EPC with EREMOVE. free_epc indicates whether to free EPC
 * pages during reset. This will be called when domain goes into S3-S5 state
 * (with free_epc being false), and when domain is destroyed (with free_epc
 * being true).
 *
 * It is possible that EREMOVE will be called for SECS when it still has
 * children present, in which case SGX_CHILD_PRESENT will be returned. In this
 * case, SECS page is kept to a tmp list and after all EPC pages have been
 * called with EREMOVE, we call EREMOVE for all the SECS pages again, and this
 * time SGX_CHILD_PRESENT should never occur as all children should have been
 * removed.
 *
 * If unexpected error returned by EREMOVE, it means the EPC page becomes
 * abnormal, so it will not be freed even free_epc is true, as further use of
 * this EPC can cause unexpected error, potentially damaging other domains.
 */
static int __domain_reset_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages, bool free_epc)
{
    struct page_list_head secs_list;
    struct page_info *epg, *tmp;
    unsigned long i;
    int ret = 0;

    INIT_PAGE_LIST_HEAD(&secs_list);

    for ( i = 0; i < epc_npages; i++ )
    {
        unsigned long gfn;
        mfn_t mfn;
        p2m_type_t t;
        int r;

        gfn = i + epc_base_pfn;
        mfn = get_gfn_query(d, gfn, &t);
        if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
        {
            printk("Domain %d: Reset EPC error: invalid MFN for gfn 0x%lx\n",
                    d->domain_id, gfn);
            put_gfn(d, gfn);
            ret = -EFAULT;
            continue;
        }

        if ( unlikely(!p2m_is_epc(t)) )
        {
            printk("Domain %d: Reset EPC error: (gfn 0x%lx, mfn 0x%lx): " 
                    "is not p2m_epc.\n", d->domain_id, gfn, mfn_x(mfn));
            put_gfn(d, gfn);
            ret = -EFAULT;
            continue;
        }

        put_gfn(d, gfn);

        epg = mfn_to_page(mfn_x(mfn));

        /* EREMOVE the EPC page to make it invalid */
        r = sgx_eremove(epg);
        if ( r == SGX_CHILD_PRESENT )
        {
            page_list_add_tail(epg, &secs_list);
            continue;
        }

        if ( r )
        {
            printk("Domain %d: Reset EPC error: (gfn 0x%lx, mfn 0x%lx): "
                    "EREMOVE returns %d\n", d->domain_id, gfn, mfn_x(mfn), r);
            ret = r;
            if ( free_epc )
                printk("WARNING: EPC (mfn 0x%lx) becomes abnormal. "
                        "Remove it from useable EPC.", mfn_x(mfn));
            continue;
        }

        if ( free_epc )
        {
            /* If EPC page is going to be freed, then also remove the mapping */
            if ( clear_epc_p2m_entry(d, gfn, mfn) )
            {
                printk("Domain %d: Reset EPC error: (gfn 0x%lx, mfn 0x%lx): "
                        "clear p2m entry failed.\n", d->domain_id, gfn,
                        mfn_x(mfn));
                ret = -EFAULT;
            }
            free_epc_page(epg);
        }
    }

    page_list_for_each_safe(epg, tmp, &secs_list)
    {
        int r;

        r = sgx_eremove(epg);
        if ( r )
        {
            printk("Domain %d: Reset EPC error: mfn 0x%lx: "
                    "EREMOVE returns %d for SECS page\n",
                    d->domain_id, page_to_mfn(epg), r);
            ret = r;
            page_list_del(epg, &secs_list);

            if ( free_epc )
                printk("WARNING: EPC (mfn 0x%lx) becomes abnormal. "
                        "Remove it from useable EPC.",
                        page_to_mfn(epg));
            continue;
        }

        if ( free_epc )
            free_epc_page(epg);
    }

    return ret;
}

static void __domain_unpopulate_epc(struct domain *d,
        unsigned long epc_base_pfn, unsigned long populated_npages)
{
    unsigned long i;

    for ( i = 0; i < populated_npages; i++ )
    {
        struct page_info *epg;
        unsigned long gfn;
        mfn_t mfn;
        p2m_type_t t;

        gfn = i + epc_base_pfn;
        mfn = get_gfn_query(d, gfn, &t);
        if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
        {
            /*
             * __domain_unpopulate_epc only called when creating the domain on
             * failure, therefore we can just ignore this error.
             */
            printk("%s: Domain %u gfn 0x%lx returns invalid mfn\n", __func__,
                    d->domain_id, gfn);
            put_gfn(d, gfn);
            continue;
        }

        if ( unlikely(!p2m_is_epc(t)) )
        {
            printk("%s: Domain %u gfn 0x%lx returns non-EPC p2m type: %d\n",
                    __func__, d->domain_id, gfn, (int)t);
            put_gfn(d, gfn);
            continue;
        }

        put_gfn(d, gfn);

        if ( clear_epc_p2m_entry(d, gfn, mfn) )
        {
            printk("clear_epc_p2m_entry failed: gfn 0x%lx, mfn 0x%lx\n",
                    gfn, mfn_x(mfn));
            continue;
        }

        epg = mfn_to_page(mfn_x(mfn));
        free_epc_page(epg);
    }
}

static int __domain_populate_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages)
{
    unsigned long i;
    int ret;

    for ( i = 0; i < epc_npages; i++ )
    {
        struct page_info *epg = alloc_epc_page();
        unsigned long mfn;

        if ( !epg )
        {
            printk("%s: Out of EPC\n", __func__);
            ret = -ENOMEM;
            goto err;
        }

        mfn = page_to_mfn(epg);
        ret = set_epc_p2m_entry(d, i + epc_base_pfn, _mfn(mfn));
        if ( ret )
        {
            printk("%s: set_epc_p2m_entry failed with %d: gfn 0x%lx, "
                    "mfn 0x%lx\n", __func__, ret, i + epc_base_pfn, mfn);
            free_epc_page(epg);
            goto err;
        }
    }

    return 0;

err:
    __domain_unpopulate_epc(d, epc_base_pfn, i);
    return ret;
}

int domain_populate_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages)
{
    struct sgx_domain *sgx = to_sgx(d);
    int ret;

    if ( !sgx )
        return -EFAULT;

    if ( domain_epc_populated(d) )
        return -EBUSY;

    if ( !epc_base_pfn || !epc_npages )
        return -EINVAL;

    if ( (ret = __domain_populate_epc(d, epc_base_pfn, epc_npages)) )
        return ret;

    sgx->epc_base_pfn = epc_base_pfn;
    sgx->epc_npages = epc_npages;

    return 0;
}

/*
 *
*
 * This function returns error immediately if there's any unexpected error
 * during this process.
 */
int domain_reset_epc(struct domain *d, bool free_epc)
{
    struct sgx_domain *sgx = to_sgx(d);

    if ( !sgx )
        return -EFAULT;

    if ( !domain_epc_populated(d) )
        return 0;

    return __domain_reset_epc(d, sgx->epc_base_pfn, sgx->epc_npages, free_epc);
}

int domain_destroy_epc(struct domain *d)
{
    return domain_reset_epc(d, true);
}

static void __detect_sgx(struct sgx_cpuinfo *sgxinfo)
{
    u32 eax, ebx, ecx, edx;
    uint64_t val;
    uint64_t sgx_enabled = IA32_FEATURE_CONTROL_SGX_ENABLE |
                           IA32_FEATURE_CONTROL_LOCK;
    int cpu = smp_processor_id();

    memset(sgxinfo, 0, sizeof(*sgxinfo));

    /*
     * In reality if SGX is not enabled in BIOS, SGX CPUID should report
     * invalid SGX info, but we do the check anyway to make sure.
     */
    rdmsrl(MSR_IA32_FEATURE_CONTROL, val);

    if ( (val & sgx_enabled) != sgx_enabled )
    {
        printk("CPU%d: SGX disabled in BIOS.\n", cpu);
        goto not_supported;
    }

    sgxinfo->lewr = !!(val & IA32_FEATURE_CONTROL_SGX_LE_WR);

    /*
     * CPUID.0x12.0x0:
     *
     *  EAX [0]:    whether SGX1 is supported.
     *      [1]:    whether SGX2 is supported.
     *  EBX [31:0]: miscselect
     *  ECX [31:0]: reserved
     *  EDX [7:0]:  MaxEnclaveSize_Not64
     *      [15:8]: MaxEnclaveSize_64
     */
    cpuid_count(SGX_CPUID, 0x0, &eax, &ebx, &ecx, &edx);
    sgxinfo->cap = eax & (SGX_CAP_SGX1 | SGX_CAP_SGX2);
    sgxinfo->miscselect = ebx;
    sgxinfo->max_enclave_size32 = edx & 0xff;
    sgxinfo->max_enclave_size64 = (edx & 0xff00) >> 8;

    if ( !(eax & SGX_CAP_SGX1) )
    {
        /* We may reach here if BIOS doesn't enable SGX */
        printk("CPU%d: CPUID.0x12.0x0 reports not SGX support.\n", cpu);
        goto not_supported;
    }

    /*
     * CPUID.0x12.0x1:
     *
     *  EAX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[31:0]
     *  EBX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[63:32]
     *  ECX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[95:64]
     *  EDX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[127:96]
     */
    cpuid_count(SGX_CPUID, 0x1, &eax, &ebx, &ecx, &edx);
    sgxinfo->secs_attr_bitmask[0] = eax;
    sgxinfo->secs_attr_bitmask[1] = ebx;
    sgxinfo->secs_attr_bitmask[2] = ecx;
    sgxinfo->secs_attr_bitmask[3] = edx;

    /*
     * CPUID.0x12.0x2:
     *
     *  EAX [3:0]:      0000: this sub-leaf is invalid
     *                  0001: this sub-leaf enumerates EPC resource
     *      [11:4]:     reserved
     *      [31:12]:    bits 31:12 of physical address of EPC base (when
     *                  EAX[3:0] is 0001, which applies to following)
     *  EBX [19:0]:     bits 51:32 of physical address of EPC base
     *      [31:20]:    reserved
     *  ECX [3:0]:      0000: EDX:ECX are 0
     *                  0001: this is EPC section.
     *      [11:4]:     reserved
     *      [31:12]:    bits 31:12 of EPC size
     *  EDX [19:0]:     bits 51:32 of EPC size
     *      [31:20]:    reserved
     *
     *  TODO: So far assume there's only one EPC resource.
     */
    cpuid_count(SGX_CPUID, 0x2, &eax, &ebx, &ecx, &edx);
    if ( !(eax & 0x1) || !(ecx & 0x1) )
    {
        /* We may reach here if BIOS doesn't enable SGX */
        printk("CPU%d: CPUID.0x12.0x2 reports invalid EPC resource.\n", cpu);
        goto not_supported;
    }
    sgxinfo->epc_base = (((u64)(ebx & 0xfffff)) << 32) | (eax & 0xfffff000);
    sgxinfo->epc_size = (((u64)(edx & 0xfffff)) << 32) | (ecx & 0xfffff000);

    return;

not_supported:
    memset(sgxinfo, 0, sizeof(*sgxinfo));
    disable_sgx();
}

void detect_sgx(struct sgx_cpuinfo *sgxinfo)
{
    if ( !opt_sgx_enabled )
    {
        setup_clear_cpu_cap(X86_FEATURE_SGX);
        return;
    }
    else if ( sgxinfo != &boot_sgx_cpudata &&
              ( !cpu_has_sgx || boot_cpu_data.cpuid_level < SGX_CPUID ))
    {
        setup_clear_cpu_cap(X86_FEATURE_SGX);
        return;
    }

    __detect_sgx(sgxinfo);
}

void disable_sgx(void)
{
    /*
     * X86_FEATURE_SGX is cleared in boot_cpu_data so that cpu_has_sgx
     * can be used anywhere to check whether SGX is supported by Xen.
     *
     * FIXME: also adjust boot_cpu_data.cpuid_level ?
     */
    setup_clear_cpu_cap(X86_FEATURE_SGX);
    opt_sgx_enabled = false;
}

static void __init print_sgx_cpuinfo(struct sgx_cpuinfo *sgxinfo)
{
    printk("SGX: \n"
           "\tCAP: %s,%s\n"
           "\tEPC: [0x%"PRIx64", 0x%"PRIx64")\n",
           boot_sgx_cpudata.cap & SGX_CAP_SGX1 ? "SGX1" : "",
           boot_sgx_cpudata.cap & SGX_CAP_SGX2 ? "SGX2" : "",
           boot_sgx_cpudata.epc_base,
           boot_sgx_cpudata.epc_base + boot_sgx_cpudata.epc_size);
}

struct ft_page {
    struct page_info *pg;
    unsigned int order;
    unsigned long idx;
    struct list_head list;
};

static int extend_epc_frametable(unsigned long smfn, unsigned long emfn)
{
    unsigned long idx;
    LIST_HEAD(ft_pages);
    struct ft_page *ftp, *nftp;
    int rc = 0;

    for ( ; smfn < emfn; smfn += PDX_GROUP_COUNT )
    {
        idx = pfn_to_pdx(smfn) / PDX_GROUP_COUNT;

        if (!test_bit(idx, pdx_group_valid))
        {
            unsigned long s = (unsigned long)pdx_to_page(idx * PDX_GROUP_COUNT);
            struct page_info *pg;

            ftp = xzalloc(struct ft_page);

            if ( !ftp )
            {
                rc = -ENOMEM;
                goto out;
            }

            pg = alloc_domheap_pages(NULL, PDX_GROUP_SHIFT - PAGE_SHIFT, 0);

            if ( !pg )
            {
                xfree(ftp);
                rc = -ENOMEM;
                goto out;
            }

            ftp->order = PDX_GROUP_SHIFT - PAGE_SHIFT;
            ftp->pg = pg;
            ftp->idx = idx;

            list_add_tail(&ftp->list, &ft_pages);

            map_pages_to_xen(s, page_to_mfn(pg),
                             1UL << (PDX_GROUP_SHIFT - PAGE_SHIFT),
                             PAGE_HYPERVISOR);
            memset((void *)s, 0, sizeof(struct page_info) * PDX_GROUP_COUNT);
        }
    }

out:
    list_for_each_entry_safe(ftp, nftp, &ft_pages, list)
    {
        if ( rc )
        {
            unsigned long s = (unsigned long)pdx_to_page(ftp->idx * PDX_GROUP_COUNT);

            destroy_xen_mappings(s, s + (1UL << PDX_GROUP_SHIFT));
            free_domheap_pages(ftp->pg, ftp->order);
        }
        list_del(&ftp->list);
        xfree(ftp);
    }

    if ( !rc )
        set_pdx_range(smfn, emfn);

    return rc;
}

static int __init init_epc_frametable(unsigned long mfn, unsigned long npages)
{
    return extend_epc_frametable(mfn, mfn + npages);
}

static int __init init_epc_heap(void)
{
    struct page_info *pg;
    unsigned long nrpages = total_epc_npages;
    unsigned long i;
    int rc = 0;

    rc = init_epc_frametable(epc_base_mfn, nrpages);

    if ( rc )
        return rc;

    for ( i = 0; i < nrpages; i++ )
    {
        pg = mfn_to_page(epc_base_mfn + i);
        pg->count_info |= PGC_epc;
    }

    init_domheap_pages(epc_base_maddr, epc_end_maddr);

    return rc;
}

struct page_info *alloc_epc_page(void)
{
    struct page_info *pg = alloc_domheap_page(NULL, MEMF_epc);

    if ( !pg )
        return NULL;

    /*
     * PGC_epc will be cleared in free_heap_pages(), so we add it back at
     * allocation time, so that is_epc_page() will return true, when this page
     * gets freed.
     */
    pg->count_info |= PGC_epc;

    return pg;
}

void free_epc_page(struct page_info *epg)
{
    free_domheap_page(epg);
}


static int __init sgx_init_epc(void)
{
    int rc = 0;

    epc_base_vaddr = ioremap_wb(epc_base_maddr,
                                total_epc_npages << PAGE_SHIFT);

    if ( !epc_base_maddr )
    {
        printk("Failed to ioremap_wb EPC range. Disable SGX.\n");

        return -EFAULT;
    }

    rc = init_epc_heap();

    if ( rc )
    {
        printk("Failed to init heap for EPC pages. Disable SGX.\n");
        iounmap(epc_base_vaddr);
    }

    return rc;
}

static int __init sgx_init(void)
{
    if ( !cpu_has_sgx )
        goto not_supported;

    if ( sgx_init_epc() )
        goto not_supported;

    print_sgx_cpuinfo(&boot_sgx_cpudata);

    return 0;
not_supported:
    disable_sgx();
    return -EINVAL;
}
__initcall(sgx_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

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

struct sgx_cpuinfo __read_mostly boot_sgx_cpudata;

static bool __read_mostly opt_sgx_enabled = false;
boolean_param("sgx", opt_sgx_enabled);

#define total_epc_npages (boot_sgx_cpudata.epc_size >> PAGE_SHIFT)
#define epc_base_mfn (boot_sgx_cpudata.epc_base >> PAGE_SHIFT)
#define epc_base_maddr (boot_sgx_cpudata.epc_base)
#define epc_end_maddr (epc_base_maddr + boot_sgx_cpudata.epc_size)

static void *epc_base_vaddr = NULL;

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

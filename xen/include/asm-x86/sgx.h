/*
 * Intel Software Guard Extensions support
 *
 * Copyright (c) 2016-2017, Intel Corporation.
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
#ifndef __ASM_X86_SGX_H__
#define __ASM_X86_SGX_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/init.h>
#include <asm/processor.h>
#include <public/hvm/params.h>   /* HVM_PARAM_SGX */

#define SGX_CPUID 0x12

/*
 * SGX info reported by SGX CPUID.
 *
 * TODO:
 *
 * SDM (37.7.2 Intel SGX Resource Enumeration Leaves) actually says it's
 * possible there are multiple EPC resources on the machine (CPUID.0x12,
 * ECX starting with 0x2 enumerates available EPC resources until invalid
 * EPC resource is returned). But this is only for multiple socket server,
 * which we current don't support now (there are additional things need to
 * be done as well). So far for simplicity we assume there is only one EPC.
 */
struct sgx_cpuinfo {
#define SGX_CAP_SGX1    (1UL << 0)
#define SGX_CAP_SGX2    (1UL << 1)
    uint32_t cap;
    uint32_t miscselect;
    uint8_t max_enclave_size64;
    uint8_t max_enclave_size32;
    uint32_t secs_attr_bitmask[4];
    uint64_t epc_base;
    uint64_t epc_size;
    bool lewr;
};

extern struct sgx_cpuinfo __read_mostly boot_sgx_cpudata;
/* Detect SGX info for particular CPU via SGX CPUID */
void detect_sgx(struct sgx_cpuinfo *sgxinfo);
void disable_sgx(void);
#define sgx_lewr() (boot_sgx_cpudata.lewr)

struct page_info *alloc_epc_page(void);
void free_epc_page(struct page_info *epg);

struct sgx_domain {
    unsigned long epc_base_pfn;
    unsigned long epc_npages;
};

struct sgx_domain *to_sgx(struct domain *d);
bool domain_epc_populated(struct domain *d);
int domain_populate_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages);
int domain_reset_epc(struct domain *d, bool free_epc);
int domain_destroy_epc(struct domain *d);

#endif  /* __ASM_X86_SGX_H__ */

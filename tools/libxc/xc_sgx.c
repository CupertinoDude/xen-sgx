/*
 * xc_sgx.c
 *
 * SGX related MSR setup
 *
 * Copyright (C) 2017      Intel Corporation
 * Author Boqun Feng <boqun.feng@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <assert.h>
#include "xc_private.h"
#include "xc_msr_x86.h"

int xc_msr_sgx_set(xc_interface *xch, uint32_t domid, bool lewr,
                   uint64_t *lehash, int max_vcpu)
{
    int rc, i, nr_msrs;
    DECLARE_DOMCTL;
    xen_domctl_vcpu_msr_t sgx_msrs[5];
    DECLARE_HYPERCALL_BUFFER(void, buffer);

    if ( !lehash && !lewr )
        return 0;

    sgx_msrs[0].index = MSR_IA32_FEATURE_CONTROL;
    sgx_msrs[0].reserved = 0;
    sgx_msrs[0].value = IA32_FEATURE_CONTROL_LOCK |
                        IA32_FEATURE_CONTROL_SGX_ENABLE |
                        (lewr ? IA32_FEATURE_CONTROL_SGX_LE_WR : 0);

    if ( !lehash )
        nr_msrs = 1;
    else
    {
        nr_msrs = 5;

        for ( i = 0; i < 4; i++ )
        {
            sgx_msrs[i+1].index = MSR_IA32_SGXLEPUBKEYHASH0 + i;
            sgx_msrs[i+1].reserved = 0;
            sgx_msrs[i+1].value = lehash[i];
        }
    }

    buffer = xc_hypercall_buffer_alloc(xch, buffer,
                                       nr_msrs * sizeof(xen_domctl_vcpu_msr_t));
    if ( !buffer )
    {
        ERROR("Unable to allocate %zu bytes for msr hypercall buffer",
              5 * sizeof(xen_domctl_vcpu_msr_t));
        return -1;
    }

    domctl.cmd = XEN_DOMCTL_set_vcpu_msrs;
    domctl.domain = domid;
    domctl.u.vcpu_msrs.msr_count = nr_msrs;
    set_xen_guest_handle(domctl.u.vcpu_msrs.msrs, buffer);

    memcpy(buffer, sgx_msrs, nr_msrs * sizeof(xen_domctl_vcpu_msr_t));

    for ( i = 0; i < max_vcpu; i++ ) {
        domctl.u.vcpu_msrs.vcpu = i;
        rc = xc_domctl(xch, &domctl);

        if (rc)
            break;
    }

    xc_hypercall_buffer_free(xch, buffer);

    return rc;
}

/*
 * xc_msr_x86.h
 *
 * MSR definition macros
 *
 * Copyright (C) 2014      Intel Corporation
 * Author Dongxiao Xu <dongxiao.xu@intel.com>
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

#ifndef XC_MSR_X86_H
#define XC_MSR_X86_H

#define MSR_IA32_TSC            0x00000010
#define MSR_IA32_CMT_EVTSEL     0x00000c8d
#define MSR_IA32_CMT_CTR        0x00000c8e

#define MSR_IA32_FEATURE_CONTROL	0x0000003a
#define IA32_FEATURE_CONTROL_LOCK                     0x0001
#define IA32_FEATURE_CONTROL_SGX_ENABLE               0x40000
#define IA32_FEATURE_CONTROL_SGX_LE_WR                0x20000

#define MSR_IA32_SGXLEPUBKEYHASH0   0x0000008c
#define MSR_IA32_SGXLEPUBKEYHASH1   0x0000008d
#define MSR_IA32_SGXLEPUBKEYHASH2   0x0000008e
#define MSR_IA32_SGXLEPUBKEYHASH3   0x0000008f

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

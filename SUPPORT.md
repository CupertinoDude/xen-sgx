# Support statement for this release

This document describes the support status
and in particular the security support status of the Xen branch
within which you find it.

See the bottom of the file
for the definitions of the support status levels etc.

# Release Support

    Xen-Version: 4.10-unstable
    Initial-Release: n/a
    Supported-Until: TBD
    Security-Support-Until: Unreleased - not yet security-supported

# Feature Support

## Host Architecture

### x86-64

    Status: Supported

### ARM v7 + Virtualization Extensions

    Status: Supported

### ARM v8

    Status: Supported

## Host hardware support

### Physical CPU Hotplug

    Status, x86: Supported

### Physical Memory Hotplug

    Status, x86: Supported

### Host ACPI (via Domain 0)

    Status, x86 PV: Supported
    Status, ARM: Experimental

### x86/Intel Platform QoS Technologies

    Status: Tech Preview

### IOMMU

    Status, AMD IOMMU: Supported
    Status, Intel VT-d: Supported
    Status, ARM SMMUv1: Supported
    Status, ARM SMMUv2: Supported

### ARM/GICv3 ITS

    Status: Experimental

Extension to the GICv3 interrupt controller to support MSI.

## Guest Type

### x86/PV

    Status: Supported

Traditional Xen PV guest

No hardware requirements

### x86/HVM

    Status: Supported

Fully virtualised guest using hardware virtualisation extensions

Requires hardware virtualisation support (Intel VMX / AMD SVM)

### x86/PVH guest

    Status: Supported

PVH is a next-generation paravirtualized mode
designed to take advantage of hardware virtualization support when possible.
During development this was sometimes called HVMLite or PVHv2.

Requires hardware virtualisation support (Intel VMX / AMD SVM)

### ARM guest

    Status: Supported

ARM only has one guest type at the moment

## Memory Management

### Dynamic memory control

    Status: Supported

Allows a guest to add or remove memory after boot-time.
This is typically done by a guest kernel agent known as a "balloon driver".

## Resource Management

### CPU Pools

    Status: Supported

Groups physical cpus into distinct groups called "cpupools",
with each pool having the capability
of using different schedulers and scheduling properties.

### Credit Scheduler

    Status: Supported

A weighted proportional fair share virtual CPU scheduler.
This is the default scheduler.

### Credit2 Scheduler

    Status: Supported

A general purpose scheduler for Xen,
designed with particular focus on fairness, responsiveness, and scalability

### RTDS based Scheduler

    Status: Experimental

A soft real-time CPU scheduler
built to provide guaranteed CPU capacity to guest VMs on SMP hosts

### ARINC653 Scheduler

    Status: Supported

A periodically repeating fixed timeslice scheduler.
Currently only single-vcpu domains are supported.

### Null Scheduler

    Status: Experimental

A very simple, very static scheduling policy
that always schedules the same vCPU(s) on the same pCPU(s).
It is designed for maximum determinism and minimum overhead
on embedded platforms.

### NUMA scheduler affinity

    Status, x86: Supported

Enables NUMA aware scheduling in Xen

## Scalability

### Super page support

    Status, x86 HVM/PVH, HAP: Supported
    Status, x86 HVM/PVH, Shadow, 2MiB: Supported
    Status, ARM: Supported

NB that this refers to the ability of guests
to have higher-level page table entries point directly to memory,
improving TLB performance.
On ARM, and on x86 in HAP mode,
the guest has whatever support is enabled by the hardware.
On x86 in shadow mode, only 2MiB (L2) superpages are available;
furthermore, they do not have the performance characteristics
of hardware superpages.

Also note is feature independent
of the ARM "page granularity" feature (see below).

### x86/PVHVM

    Status: Supported

This is a useful label for a set of hypervisor features
which add paravirtualized functionality to HVM guests
for improved performance and scalability.
This includes exposing event channels to HVM guests.

# Format and definitions

This file contains prose, and machine-readable fragments.
The data in a machine-readable fragment relate to
the section and subsection in which it is found.

The file is in markdown format.
The machine-readable fragments are markdown literals
containing RFC-822-like (deb822-like) data.

## Keys found in the Feature Support subsections

### Status

This gives the overall status of the feature,
including security support status, functional completeness, etc.
Refer to the detailed definitions below.

If support differs based on implementation
(for instance, x86 / ARM, Linux / QEMU / FreeBSD),
one line for each set of implementations will be listed.

## Definition of Status labels

Each Status value corresponds to levels of security support,
testing, stability, etc., as follows:

### Experimental

    Functional completeness: No
    Functional stability: Here be dragons
    Interface stability: Not stable
    Security supported: No

### Tech Preview

    Functional completeness: Yes
    Functional stability: Quirky
    Interface stability: Provisionally stable
    Security supported: No

#### Supported

    Functional completeness: Yes
    Functional stability: Normal
    Interface stability: Yes
    Security supported: Yes

#### Deprecated

    Functional completeness: Yes
    Functional stability: Quirky
    Interface stability: No (as in, may disappear the next release)
    Security supported: Yes

All of these may appear in modified form.
There are several interfaces, for instance,
which are officially declared as not stable;
in such a case this feature may be described as "Stable / Interface not stable".

## Definition of the status label interpretation tags

### Functionally complete

Does it behave like a fully functional feature?
Does it work on all expected platforms,
or does it only work for a very specific sub-case?
Does it have a sensible UI,
or do you have to have a deep understanding of the internals
to get it to work properly?

### Functional stability

What is the risk of it exhibiting bugs?

General answers to the above:

 * **Here be dragons**

   Pretty likely to still crash / fail to work.
   Not recommended unless you like life on the bleeding edge.

 * **Quirky**

   Mostly works but may have odd behavior here and there.
   Recommended for playing around or for non-production use cases.

 * **Normal**

   Ready for production use

### Interface stability

If I build a system based on the current interfaces,
will they still work when I upgrade to the next version?

 * **Not stable**

   Interface is still in the early stages and
   still fairly likely to be broken in future updates.

 * **Provisionally stable**

   We're not yet promising backwards compatibility,
   but we think this is probably the final form of the interface.
   It may still require some tweaks.

 * **Stable**

   We will try very hard to avoid breaking backwards  compatibility,
   and to fix any regressions that are reported.

### Security supported

Will XSAs be issued if security-related bugs are discovered
in the functionality?

If "no",
anyone who finds a security-related bug in the feature
will be advised to
post it publicly to the Xen Project mailing lists
(or contact another security response team,
if a relevant one exists).

Bugs found after the end of **Security-Support-Until**
in the Release Support section will receive an XSA
if they also affect newer, security-supported, versions of Xen.
However, the Xen Project will not provide official fixes
for non-security-supported versions.

Three common 'diversions' from the 'Supported' category
are given the following labels:

  * **Supported, Not security supported**

    Functionally complete, normal stability,
    interface stable, but no security support

  * **Supported, Security support external**

    This feature is security supported
    by a different organization (not the XenProject).
    See **External security support** below.

  * **Supported, with caveats**

    This feature is security supported only under certain conditions,
    or support is given only for certain aspects of the feature,
    or the feature should be used with care
    because it is easy to use insecurely without knowing it.
    Additional details will be given in the description.

### Interaction with other features

Not all features interact well with all other features.
Some features are only for HVM guests; some don't work with migration, &c.

### External security support

The XenProject security team
provides security support for XenProject projects.

We also provide security support for Xen-related code in Linux,
which is an external project but doesn't have its own security process.

External projects that provide their own security support for Xen-related features are listed below.

  * QEMU https://wiki.qemu.org/index.php/SecurityProcess

  * Libvirt https://libvirt.org/securityprocess.html

  * FreeBSD https://www.freebsd.org/security/

  * NetBSD http://www.netbsd.org/support/security/

  * OpenBSD https://www.openbsd.org/security.html

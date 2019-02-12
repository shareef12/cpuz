# CPU-Z Exploit (CVE-2017-15302 & CVE-2017-15303)

Local privilege escalation exploit for the CPU-Z kernel driver.

The CPU-Z application will install a vulnerable signed driver to access kernel
data from usermode. Before v1.81, the CPU-Z driver exposed three IOCTLs that
allow any usermode application to read control registers, read DWORDs from
physical memory, and write DWORDs to physical memory. We abuse this
functionality to gain full kernel mode code execution and spawn a SYSTEM shell
as a proof of concept.

This exploit supports Windows XP - Windows 10 1607:
 - x86
 - x86+PAE
 - x86\_64

This exploit was tested on the following systems with CPU-Z v1.76:
 - Windows 10 Kernel Version 10586 (x86 PAE) - 10586.162.x86fre.th2\_release\_sec.160223-1728
 - \*Windows 10 Kernel Version 16299 (x86\_64) - 16299.15.amd64fre.rs3\_release.170928-1534

\* On Windows 1703 and later kernel control flow guard (CFG) is enabled by
   default [1], resulting in a KERNEL\_SECURITY\_CHECK\_FAILURE bug check.


## Usage

To run this exploit, start the CPU-Z application, and run Exploit.exe from a
command prompt as a normal user. If successful, it should spawn a new cmd.exe
process running as SYSTEM. Note that this exploit will fail if run from a
low-integrity process due to the use of NtQuerySystemInformation.


## Implementation Details

The CPU-Z kernel driver before v1.81 allows any usermode application to read
control registers, read DWORDs from physical memory, and write DWORDs to
physical memory. We abuse this functionality to read cr3 and traverse the page
tables in order to build an arbitrary read/write primitive over the entire
virtual memory space.

With full read/write, we flip the user/supervisor bit on the page table entry
(PTE) containing our payload to KernelMode to bypass Supervisor Mode Execution
Prevention (SMEP). We then overwrite a function pointer at
nt!HalDispatchTable[1] and trigger the payload by calling
NtQueryIntervalProfile.

As a proof of concept, the payload will assign the SYSTEM token to a suspended
cmd.exe process, and resume the process. This should result in a new command
prompt running as NT Authority/System. The payload does not rely on static
offsets and should thus work on Windows XP+.


## Mitigations

A number of mitigations have been introduced over the last two years that limit
the effectiveness of this exploit. A brief description is below.

1. As of version 1.81, the driver provided with CPU-Z has been patched to limit
   the set of callers that can open its device object and some IOCTL
   implementations have been removed. On requests to open the driver's device
   object, it will check to see if the current process has the
   SeLoadDriverPrivilege enabled. If this privilige is missing or disabled, the
   driver will reject the request with STATUS\_ACCESS\_DENIED. Note that when
   running as an Administrator, it is trivial to enable this privilege from
   usermode. Furthermore, the IOCTL to read control registers has been removed
   (although the physical memory read/write implementations remain). Without the
   ability to read the page table base from cr3, the exploitation method in this
   project is no longer feasible. Note that the CPU-Z driver provides numerous
   other IOCTLs that could be used for exploitation, such as reading from and
   writing to arbitrary model-specific registers.

2. As of Windows 10 1703 (Creators Update), kernel control flow guard is
   enabled by default on x86\_64. Calls through the HalDispatchTable will
   result in a KERNEL\_SECURITY\_CHECK\_FAILURE bug check since it is
   protected by CFG. If Virtualization Based Security (VBS) is not enabled,
   it should be possible to add the payload as a valid call target to bypass
   CFG.

3. If Virtualization Based Security (VBS) is enabled it will kill the majority
   of this exploit. The PTE manipulation used to disable SMEP will no longer be
   possible, as the PTEs will be protected by the hypervisor. Additionally, a
   CFG bypass will be needed on x86\_64 to gain code execution through the
   HalDispatchTable since the kernel CFG bitmap will not be writable.


## Links

The vulnerabilities used in this exploit are detailed in CVE-2017-15302 and
CVE-2017-15303. Another proof of concept can be viewed at CPUZ-DSEFix [5].

[1] https://community.osr.com/discussion/283374/control-flow-guard-question  
[2] https://www.cvedetails.com/cve/CVE-2017-15302/  
[3] https://www.cvedetails.com/cve/CVE-2017-15303/  
[4] https://github.com/akayn/Bugs/blob/master/CPUID/CVE-2017-15302/README.md  
[5] https://github.com/SamLarenN/CPUZ-DSEFix  

Additionally, the HalDispatchTable overwrite method used in this exploit is a
commonly used vector to obtain code execution from a kernel read/write
primitive. For additional details on this technique, see the below resources.

[6] http://poppopret.blogspot.com/2011/07/windows-kernel-exploitation-basics-part.html  
[7] https://www.abatchy.com/2018/01/kernel-exploitation-7  
[8] https://osandamalith.com/2017/06/14/windows-kernel-exploitation-arbitrary-overwrite/  
[9] https://rootkits.xyz/blog/2017/09/kernel-write-what-where/  

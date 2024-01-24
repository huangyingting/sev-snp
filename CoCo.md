# AKS Confidential Container Explained

Azure Kubernetes Service (AKS) recently introduced a new preview feature called Confidential Containers.

Confidential Containers provide a set of features and capabilities to further secure your standard container workloads to achieve higher data security, data privacy and runtime code integrity goals. 

While [Confidential Containers (preview) with Azure Kubernetes Service (AKS)](https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview) has a good overview of the feature, this article will go into more details on how it works, and part of the work are based on my own understanding and research.

## AKS Confidential Container Architecture
AKS Confidential Container is based on Kata Containers, Kata Containers is a lightweight virtual machine (VM) implementation that is optimized for running containers, Kata Containers is a community project and has a lot of contributors, it is not a Microsoft project, but Microsoft has a forked repo with some features added to support AKS Confidential Container, and the repo is [microsoft/kata-containers](https://github.com/microsoft/kata-containers), and the repo is used by AKS Confidential Container.

On a very high level view, AKS Confidential Container is based on below projects
[Kata Containers](https://github.com/microsoft/kata-containers), this repo is a Microsoft forked repo with features added to support AKS confidential container like opa policy, kata containers itself is an open source project and community working to build a standard implementation of lightweight Virtual Machines (VMs) that feel and perform like containers, but provide the workload isolation and security advantages of VMs.
[Confidential Containers](https://github.com/confidential-containers/), an open source community working to enable cloud native confidential computing by leveraging Trusted Execution Environments to protect containers and data.
[Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor), an open source Virtual Machine Monitor (VMM) that runs on top of the KVM hypervisor and the Microsoft Hypervisor (MSHV).
[CBL-Mariner](https://github.com/microsoft/CBL-Mariner), an internal Linux distribution for Microsoft’s cloud infrastructure and edge products and services.

At hardware level, AKS Confidential Container currently requires AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP) with nested hypervisor support, from Azure, only Confidential child capable VMs DCas_cc_v5 and DCads_cc_v5-series support those hardware requirements, DCas_cc_v5 and DCads_cc_v5-series are available from those regions – East US, West US, North EU, West EU and Central India.

**NOTE**: 
Although Microosft document [DCas_cc_v5 and DCads_cc_v5-series (Preview)](https://learn.microsoft.com/en-us/azure/virtual-machines/dcasccv5-dcadsccv5-series) states `Confidential child capable VMs are currently enabled only through Azure Kubernetes Service (AKS) when you choose these VMs as your agent node sizes`, however it is not true, you can create a VM with DCas_cc_v5 or DCads_cc_v5-series, but you can not run Confidential Container on it, because AKS Confidential Container requires a special image with `kernel-mshv.x86_64` support, and the image is only available from AKS.

DCas_cc_v5 and DCads_cc_v5-series are not `Confidential virtual machine`, its security type is `Standard`

The overall architecture of AKS Confidential Container is shown below.
![CoCo-Architecture](/images/CoCo-Architecture.svg)

[Security policy for Confidential Containers on Azure Kubernetes Service](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers-aks-security-policy) has a more detailed diagram on the architecture.
![AKS-CoCo-Architecture](https://learn.microsoft.com/en-us/azure/confidential-computing/media/confidential-containers-security-policy/security-policy-architecture-diagram.png)

## AKS Confidential Container Components Explained
[Kata Containers Architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md)

### containerd-shim-kata-v2
A container runtime shim is a piece of software that resides in between a container manager (containerd, cri-o, podman) and a container runtime (runc, crun) solving the integration problem of these counterparts.`containerd-shim-kata-v2`, implements the Containerd Runtime V2 (Shim API) for Kata. With `containerd-shim-kata-v2`, Kubernetes can launch Pod and OCI compatible containers with one shim (the shimv2) per Pod.

containerd, the daemon, does not directly launch containers. Instead, it acts as a higher-level manager or hub for coordinating the activities of containers and content, that lower-level programs, called "runtimes", actually implement to start, stop and manage containers, either individual containers or groups of containers, e.g. Kubernetes pods.
[Runtime v2](https://github.com/containerd/containerd/tree/main/runtime/v2)

### Cloud Hypervisor
When launch a Pod and OCI compatible containers, `containerd-shim-kata-v2` will launch a lightweight virtual machine, and use the guest's Linux kernel to create a container workload, `cloud-hypervisor` is the Virtual Machine Monitor (VMM) that is used to manage the lightweight virtual machine. In AKS Confidential Container, `cloud-hypervisor` relies on Microsoft Hypervisor (mshv) to support nested virtualization, and security features like AMD's SEV-SNP. This special version of `cloud-hypervisor` is built with features flags `mshv`, `igvm` and `sev_snp`.

For more details, see
[Microsoft Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/mshv.md)
[Virtualization in Kata Containers](https://github.com/kata-containers/kata-containers/blob/main/docs/design/virtualization.md)

### CBL-Mariner
CBL-Mariner is an internal Linux distribution for Microsoft’s cloud infrastructure and edge products and services. CBL-Mariner is used to build the image for AKS Host and Confidential Container.

Host image - `5.15.126.mshv9-2.cm2`
Guest image - `6.1.0.mshv14`

### Kata Agent
The Kata agent is a long running process that runs inside the Virtual Machine (VM) (also known as the "pod" or "sandbox").

The agent is packaged inside the Kata Containers guest image which is used to boot the VM. Once the runtime has launched the configured hypervisor to create a new VM, the agent is started. From this point on, the agent is responsible for creating and managing the life cycle of the containers inside the VM.

There is a need for processes in the virtual machine can communicate with processes in the host. In AKS Confidential Container, `kata-agent` communicates Kata Containers runtime (`containerd-shim-kata-v2`) using ttrpc over vsock.

For more details, see [Kata Containers and VSOCKs
](https://github.com/kata-containers/kata-containers/blob/main/docs/design/VSocks.md)

### OPA Agent
In AKS Confidential Containers, the Kata agent API self-protection is implemented using a security policy (also known as the Kata Agent Policy), specified by the owners of the confidential pods. The policy document contains rules and data corresponding to each pod, using the industry standard Rego policy language. The enforcement of the policy inside the guest VM is implemented using the Open Policy Agent (OPA) agent.

## References

[Red Hat OpenShift sandboxed containers: Peer-pods technical deep dive](https://www.redhat.com/en/blog/red-hat-openshift-sandboxed-containers-peer-pods-technical-deep-dive)
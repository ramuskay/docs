# CKS


## Security principles

- Defense in Depth
- Least privilege
- Limiting the attack surface

There is an extra layer of security on kube of course  
For :  
- Host : Only kube running, SSH access restricted etc..
- Kube :
    - restricted access to apiserver, kubelet and etcd. 
    - Authentication -> Autorization. 
    - Admission controller : nodeRestriction and custom policies (OPA). 
    - Encrypted etcd
- Application security : 
    - No secrets in it
    - RBAC
    - Container sandboxing + hardening (immutable)
    - Vulneraiblity scanning
    - mtls

The CA inside the cluster is really imnportant, it certifies : 
- Apiserver (svr+clt)
- Kubelet (srv+clt)
- Scheduler (clt)
- Etcd (srv)
- etc...

Most of those certificates can be found on the master node in /etc/kubernetes/pki.  There is the one of : 
- CA
- API server
- Etcd server

For the scheduler clt it's on the  /etc/kubernetes/scheduler.conf, same for controller-manager ( /etc/kubernetes/controller-manager.conf
)  
For kubelet : /etc/kubernetes/kubelet.conf and /var/lib/kubelet/pki

## Container

For remainder for container the kernel is shared between the containers  
Namespaces : Isolate processes  
cgroups : Restrict the resource usage (RAM, CPU)

Container tool versus : 
- Docker : Contaienr runtime + tool to manage containers
- Containerd : Container runtime
- Crictl : CLI to manage container
- Podman : Tool to manage containers

Podman + containerd = <3

"Containers are not contained"   
- A rogue kernel is impacting all the pods of the same node
- The workflow is : *Docker's process* --> **System calls --> Kernel** --> Hardware
  - **Kernel space** and *user space*
- A sandbox can be use between process and system calls to avoid container to access directly to syystem calls
  - More resources needed
  - Might be better smaller containers
  - Not good for syscall heavy load
  - No direct access to hardware

OCI : Open Container Initiative
- Specification (what is a image ,runtime etc...)

CRI : Container runtime inteface
![alt text](image-1.png)

### Sandbox
- Katacontainers : 
  - Each containers is running in a virtual machines with its own kernel (strong seperation layer)
  - QEMU as default (nested virtu in the cloud)
- gVisor
  - "Kernel-space in the user space"
  - Another type of seperation (not a VM)
  - Simulate kernel syscalls with limited func in the usr space
  - Runtime is runc
- To configure it, you need to use `runtimeClass`

### Image footprint

Containers images are just layers  
`FROM` --> import an image  
`RUN`, `COPY`, `ADD` --> are the only command that are adding layers

Multi stage build can be useful to lightweight the size of an image : 
```
FROM golang:1.23
WORKDIR /src
COPY <<EOF ./main.go
package main

import "fmt"

func main() {
  fmt.Println("hello, world")
}
EOF
RUN go build -o /bin/hello ./main.go

FROM scratch
COPY --from=0 /bin/hello /bin/hello
CMD ["/bin/hello"]
```
Here we using golang image to build the src and then scratch image to run it (it will reduce the size of the image in the end)

### Image hardening

- Never use `latest` tag
- Don't run as root by default (`USER` command) 
- Make filesystem readonly (in k8s with security context) with `chmod a-w /etc` for ex
- Remove shell access with `nologin`

Scan vulnerabilities can be done at : 
- Build level
  - Can be done at repository level aync
- Deploy level
- Code level

Tool to check vuln
- Clair (hard)
- Trivy (easy)
  - Scan public repo you can list vuln of nginx for ex

External services can check if image are allowed to be used

### Syscalls, processes, strace etc...

syscalls --> (reboot, fstat, write etc...)  
strace --> intercept syscall made by a process  
`strace -cw ls /` --> great ouput to sum the elapse time  

/proc directory (contains file that doesn't exist)
- All the directories in /proc correspond to a process
- `fd` directory is related to all the file descriptors that are doing syscalls done by the process. When we open an existing file or create a new file, the kernel returns a file descriptor to the process
- `environ` directory is related to the env variables that the process have access to (**secret can be read from anyone having access of the /proc of the host**) 
- The complete list can be found [here](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/5/html/deployment_guide/s1-proc-directories#s2-proc-processdirs) : 

Falco
- CNCF tool
- Deep kernel tracing build on Linux kernel
- Detect bahavior, security rules etc...

### Immutability

Def : Container cannot be modified during its  lifetime  
Instead of ssh, stop and start we should create and delete instances  
Advantages : 
- Advance deploy methods
- Easy rollback
- More reliable
- Better sec on container level

To enforce immutability : 
- Remove shell (use a `StartupProbe`)
- Make fs ro
  - Through securityContext (`readOnlyRootFilesytem: true`)
  - We can still allow some directory to be writable (logs for ex) through empty dirs
- Run as user and non root

We can :
- Use a StartupProbe (will be exected before readiness and liveness like init container) and execute something like `chmod a-w -R /`
- Move logic in initContainer if we need read write before executing the process

## Network Policies

- Firewall rules in K8s
- Only valid in one ns
- Implemented by the CNI
- By default pods <--> pods is allowed. Pods are not isolated
    - On the other hand as soon a netpol is defined default is **deny**

## GUI

`kubectl port-forward` : TO redirect a local port (e.g. 1234) to a cluster pod port (10.224.10.25:443)

## RBAC

`view` is one clusterrole avec ro on the whole cluster

## Ingress

With nginx ingress you can modify the exposed certificate by configuring it in (spec.tls)

## CIS Benchmark

CIS : Center for Internet Security
- Best practise for the secure conf of a system
- Consensus between a large panel of actors

They provide default k8s security rules that we can apply out of the box, but also as a base and then customize   
kube-bench is a tool that can apply rule for you  

## RBAC

A general concept to control access
- It's based on whitelisting (allowing and denying by default)
- Role and ClusterRole (namespace vs non namespace rule) with the RoleBinding and ClusterRoleBinding to bind the role to "smth"
    - So with Role you are applying in only one namespace : user has same permission in one ns
    - With ClusterRole + ClusterRoleBinding it's on the whole cluster (ns + non ns) : user has same permission in all ns
    - ClusterRole and Rolebinding can be linked to : user has same permission in multiple ns
    - Role and Rolebinding cannot be linked
- The permissions are : can edit pods, can read secrets etc...
- Permission are additive
    - ClusterRole (get+delete secrets) + Role (get secrets) = get and delete secrets
- Always test the RBAC rules

Two types of "account"  
- ServiceAccount : "robotic" account, managed by the k8s api
    - Are namespaced
    - One "default" in every ns
    - Can be used to talk to API
    - To create its token (`k create token <sa>`), it will then be mounted in any pod that have the sa configured
    - Checking sa permissions with `k auth can-i delete secrets --as system:serviceaccount:<ns>:<SA_NAME>`
- "Normal User" : There is no such thing as user, it's just a certificate
    - The certificate should be issued by the cluster CA
    - First we need to create a CSR and send it to the API through the CertificateSigningRequest kind (kubectl certificate approve)
    - Then we can DL the CRT
    - We cannot invalidate a certificate, so in case of a leak we can
        - Remove all its access via RBAC
        - Username cannot be used until cert expired
        - Create new CA and re-issue all certs 


## Request

![Request workslow](image.png)

Either took by :
- A normal user
- A SA
- Anonymous used
But always authenticated  

Restictions : 
- DOn't allow anonymous
- Close insecure port
- Don't expose API ouside
- Restrict access from nodes to API
Minors ones : 
- Use RBAC to secure
- Prevent pods from accessing the API
- API server behind firewall / whitelist

By default : 
- Anonymous access is allow but authenticated as anonymous and has no default rights
  - In the kubeapi-server manifest `- --authorization-mode=Node,RBAC` --> Allow only RBAC and node to access the API 
  - Can be disallow by `--anonymous-auth=false`
- Insecure access is disable by default, it allows : 
  - Http
  - Bypassing authentication and authorization module
  - Only to be used for debugging

Here an example of manual authentication : 
`curl -k https://192.168.39.102:8443 --key /home/lief/.minikube/profiles/minikube/client.key --cert /home/lief/.minikube/profiles/minikube/client.crt --cacert /home/lief/.minikube/ca.crt`

### Node restriction

- Controlled by `enable-admission-plugins=NodeRestriction`
- Limit the node labels a kubelet can modify 
    - Only the one from the own node
    - Cannot start with node-restriction.kubernetes.io
- It allows ensuring secure workload isolation via labels

## Updates

- No LTS
- Minor version every 3 months (major.minor.patch)
- Maintenance for the last 3 realeases
- Order : 
    - First master comnponent
    - Then worker components
    - Kubectl at the end v
    - Should be same version minor version in a ideal world
- How to : 
    - `kubectl drain`
    - Upgrade
    - `kubectl uncordon`
- Check PDB, grace-period etc...
- For the exam search for : "Upgrading kubeadm clsuters" 

## Secrets

- Can be link to a pod through env var or file
- Can be found on the worker node itself by using `crictl`
- Secrets are stored unencrypted in etcd (`etcdctl get /registry/secrets/default/secret1`) 
-  To encrypt it we need to use a `EncryptionConfiguration` manifest on the resource "secrets"
    - Be careful the first provider of `EncryptionConfiguration` will be used (indentity provider is uncrypted)
    - To add the new `EncryptionConfiguration` we have to add this to the kube-apiserver manifest through `--encryption-provider-config`
    - We can replace all secret with the new provider with `k get secret -A -o yaml | kubectl replace -f -
- Configmap vs Secrets
    - Configmap should stay as they are
    - Secrets have multiple ways to be implemented

## Security context

Define privligege and access contreol
- userid and groupid
- Capabitilies (e.g NET_ADMIN)
- Run privileged or unprivileged
  - By default docker run "unprivileged" (as k8s)
  - It can be run as privileged to : 
    - Access all devices
    - Run docker daemon inside container
  - Privileged means **root 0 of the container is mapped to host root 0**  
  - PrivilegeEscalation means **it ensures that no child process can gain more permissions than its parent.**. For instance from 1000 user start a new shell with the user 0
    - `AllowPrivilegeEscalation` controls priv escalation (default to true, more info [here](https://blog.christophetd.fr/stop-worrying-about-allowprivilegeescalation/))
  - 


## mTLS 

- Mutual auth
- Two ways
- Auth seach other at the same time

For that we needs : 
- Client cert & server cert + CA
- Rotate those certs

We can use a proxy inside the pod (e.g istio, linkerd) with a cert tool (e.g certmanager) as  a man in the middle  
Example of setup : iptables with an init container which is (with NET_ADMIN) redirect traffic to the proxy

## OPA

OPA stands for Open Policy Agent allow us to right custom rules
- It's not Kubernetes specific
- Easy implem of policies (rego langage)
- Works with JSON/YAML
- In K8s it uses admission controllers [step](#request) 

### Gatekeeper

It make it easier to use OPA in K8S
Workflow : `ConstraintTemplate` --> `Constraint`  
Admission webhook in the third [step](#request) : 
- Validating webhook --> accept or deny
- Mutating webhook --> Mutate a object (e.g add a label)

Rego playground to test your rules  
(note the policy that prvent create resource in the default ns are interesting for the lab)  

## Static Analysis of user workloads

- Looks at source code and text files
- Check against rules (OPA, Kubernetes Policy Admission)

For ex : 
- Always define resource requests and limits
- Pods should never use the `default` sa

Always good to do this at early stage of the pipeline

### Tools

Kubesec : 
- Sec risk analysis
- Sopen source
- Opiniated

Conftest :
- Unit test framework for k8s
- From OPA
- Use rego

## Audit

All the actions made towards the Kubernetes API can be logged into the audit logs  
Each request can be recorded with an associated stage. The defined stages are:

- RequestReceived : The stage for events generated as soon as the audit handler receives the request, and before it is delegated down the handler chain.
- ResponseStarted : Once the response headers are sent, but before the response body is sent. This stage is only generated for long-running requests (e.g. watch).
- ResponseComplete : The response body has been completed and no more bytes will be sent.
Panic - Events generated when a panic occurred.

The defined audit levels are:

- None : Don't log events that match this rule.
- Metadata : Log events with metadata (requesting user, timestamp, resource, verb, etc.) but not request or response body.
- Request : Log events with request metadata and body but not response body. This does not apply for non-resource requests.
- RequestResponse : Log events with request metadata, request body and response body. This does not apply for non-resource requests.

## Hardening tools

Between userspace and kernel space tools to harden

### AppArmor

To allow certain request and restric other  
Base on profile, two modes (like selinux): 
- Unconfined: Process can escape
- Complain : Process can escape but will be logged
- Enforce  : Process cannot escape

aa-genprof --> generate profile for a binary (`aa-genprof curl`)
aa-status --> to see all the profiles
aa-logprof --> update profile based on syslog

All the profile are in /etc/apparmor.d 

We can use on kube for pods if : 
- Containers runtime needs to support apparmor
- Apparmor needs to be installed on every node
- Apparmor proiles needs to be available on every nodes
- Apparmor profiles are speicified on each container through securityContext 

```
securityContext:
  appArmorProfile:
    type: <profile_type>
```

### Seccomp

Secure comnputing mode, we can select wich syscall can be used by the process (forbid write() or exec())  
Can be combined with BPF filter

Can be used through:
```
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
```

## Reduce attack surface

- Application need to be up2date (+kernel)
- Remove not needed package
- Worker node run only k8s components
- Node recycling and should be ephemeral




[Video progress](https://youtu.be/d9xfB5qaOfg?t=30723)

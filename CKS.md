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


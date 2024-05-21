# AWRBACS
AWACS for RBAC. Tool for auditing CRUD permissions in Kubernetes' RBAC.

<p align="center"><img width=450 alt="AWRBACS" src="awrbacs_logo.png"></p>

# Install

```
git clone https://github.com/lobuhi/awrbacs
cd awrbacs
go build .
```

## How to

Usage of ./awrbacs:

```
  -as value
        Usernames to impersonate
  -auto
        Automatically enumerate all Users and ServiceAccounts in RoleBindings and ClusterRoleBindings
  -f string
        Path to a file containing a list of users to check
  -kubeconfig string
        Path to the kubeconfig file (default "$HOME/.kube/config")
  -no-kube-system
        Do not check system:* users nor ServiceAccounts in kube-system.
  -sa value
        Service accounts to impersonate in the format namespace:serviceaccount
  -self
        Use current kubeconfig context
```

Examples:

Test multiple users and serviceaccounts:
```
awrbacs -sa kube-system:root-ca-cert-publisher -as jane -sa kube-system:replicaset-controller -sa prod:prod-sa -as bob
```

Find subjects defined in RoleBindings and ClusterRoleBindings and omit those users defined as `system:*` or serviceaccounts in `kube-system` namespace:
```
awrbacs -auto --no-kube-system 
```



# Standalone mode

```
kc config https://okit.ingress.kubo6.mbp/kubeconfig --force --standalone

kubectl oidc-login

kubectl get ns

```

No logout, except cleanup kubeconfig


# Direct mode

```

make build && ./bin/kc config https://okit.ingress.kubo6.mbp/kubeconfig --force

kubectl get ns


```

Logout:

kubectl oidc-login clean


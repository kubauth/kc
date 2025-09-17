```
cd /Users/sa/dev/d1/git/kc
export KUBECONFIG=/Users/sa/dev/d1/git/kc/tmp/config-empty.yaml

make build && ./bin/kc token --issuerURL https://kubauth.ingress.kubo5.mbp --clientId weboidc0 --clientSecret my-secret

export KUBECONFIG=

make build && ./bin/kc token --issuerURL https://kubauth.ingress.kubo5.mbp --clientId weboidc0 --clientSecret my-secret


make build && ./bin/kc logout

```


```
cd /Users/sa/dev/d1/git/kc
export KUBECONFIG=/Users/sa/dev/d1/git/kc/tmp/config-kubelogin.yaml

make build && ./bin/kc config https://okit.ingress.kubo6.mbp/kubeconfig --force

kubectl get ns

kubectl oidc-login clean

make build && ./bin/kc token --clientId weboidc0 --clientSecret my-secret
make build && ./bin/kc token-nui --clientId weboidc0 --clientSecret my-secret --logLevel debug --login sa --password as


```



```
cd /Users/sa/dev/d1/git/kc
export KUBECONFIG=/Users/sa/dev/d1/git/kc/tmp/config-standalone.yaml

make build && ./bin/kc config https://okit.ingress.kubo6.mbp/kubeconfig --standalone --force

make build && ./bin/kc token --clientId weboidc0 --clientSecret my-secret
make build && ./bin/kc token-nui --clientId weboidc0 --clientSecret my-secret --logLevel debug --login sa --password as


kubectl get ns

kubectl oidc-login 

kubectl oidc-login --standalone clean



```
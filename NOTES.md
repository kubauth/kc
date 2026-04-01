

```
kubectl apply -f - <<EOF
apiVersion: kubauth.kubotal.io/v1alpha1
kind: OidcClient
metadata:
  name: kc-test
  namespace: kubauth
spec:
  redirectURIs:
    - "http://127.0.0.1:9921/callback"
    - "http://127.0.0.1:9922/callback"
  grantTypes: [ "implicit", "refresh_token", "authorization_code", "password" ]
  responseTypes: [ "id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token" ]
  scopes: [ "openid", "offline", "profile", "groups", "email", "offline_access" ]
  description: A test OIDC public client
  forceOpenIdScope: false
  accessTokenLifespan: 30s
  refreshTokenLifespan: 30s
  idTokenLifespan: 10m0s
  public: true
EOF

```

```
make build && ./bin/kc token --issuerURL https://kubauth.ingress.kubo5.mbp --clientId kc-test --ttl 30m -d
```


```
make build && ./bin/kc token-nui --issuerURL https://kubauth.ingress.kubo5.mbp --clientId kc-test --ttl 30m --login admin --password admin -d
```
# keycloak-test
A HTTP Server to test Authentication and Authorization using Keycloak.
Modeled after the server implemented the the tn_inventory_service.

# cURL to get JWT
```
curl -L -X POST 'http://{HOST}/auth/realms/{{REALM}/protocol/openid-connect/token' \
-H 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id={KEYCLOAK ClientID}' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'client_secret={KEYCLOAK ClientID Secret}' \
--data-urlencode 'scope=openid' \
--data-urlencode 'username={USERNAME}' \
--data-urlencode 'password={PASSWORD}' | jq '.'
```

# cURL to get access_token from JWT
```
curl -L -X POST 'http://{HOST}/auth/realms/{{REALM}/protocol/openid-connect/token' \
-H 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id={KEYCLOAK ClientID}' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'client_secret={KEYCLOAK ClientID Secret}' \
--data-urlencode 'scope=openid' \
--data-urlencode 'username={USERNAME}' \
--data-urlencode 'password={PASSWORD}' | jq '.access_token'
```

# cURL to test server
```
curl -v -X GET http://127.0.0.1:{PORT}/{ROUTE} \
-H 'Accept: application/json' \
-H "Authorization: Bearer {access_token from cURL call above}"
```

# Routes
- ping
- docs

# Host
- auth.magna5.cloud

# Realm
- Telecom

# Docker
```
$ docker build -t keycloak-test .
$ docker run -d --rm -p 8001:8001 --name keycloak-test keycloak-test
```

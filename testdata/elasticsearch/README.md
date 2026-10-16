# Elasticsearch unauth / auth test fixture

Official Elasticsearch 8.15.3 nodes for validating Nerva's
`elasticsearch-no-auth` finding (ENG-9055).

This fixture does not mock the protocol. It runs Elastic's published
image with the documented security settings:

| Port  | Security                         | GET /                                      | Finding ID              |
|-------|----------------------------------|--------------------------------------------|-------------------------|
| 19200 | `xpack.security.enabled=false`   | HTTP 200, `"tagline": "You Know, for Search"` | `elasticsearch-no-auth` |
| 19201 | `xpack.security.enabled=true`    | HTTP 401, `"type": "security_exception"`   | (must not emit)         |

HTTP TLS is off on both nodes so the probe sees those status codes
instead of a failed handshake. Ports bind to `127.0.0.1` only.

Sources:

- [Install Elasticsearch with Docker](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic)
- [Security settings](https://www.elastic.co/guide/en/elasticsearch/reference/8.15/security-settings.html)
- Root API (`GET /`) tagline `"You Know, for Search"`
- Unauthenticated REST with security on: HTTP 401 `security_exception`
  (`missing authentication credentials for REST request`)

## Manual run

Each node wants about 1 GB. Docker Desktop should have ≥4 GB allocated.

```bash
docker compose -f testdata/elasticsearch/docker-compose.yml up -d --wait

curl -s http://127.0.0.1:19200/
# HTTP 200 JSON including "tagline" : "You Know, for Search"

curl -s -D- http://127.0.0.1:19201/
# HTTP 401 JSON including "type" : "security_exception"

./nerva --misconfigs --json -t 127.0.0.1:19200,127.0.0.1:19201

docker compose -f testdata/elasticsearch/docker-compose.yml down
```

Expected Nerva result:

- `127.0.0.1:19200` emits `elasticsearch-no-auth`
- `127.0.0.1:19201` does not emit that ID

## Integration test

```bash
go test -count=1 -timeout 15m -tags integration ./pkg/plugins/services/http \
  -run TestElasticsearch
```

Skipped under `-short`. Requires Docker and a pull of
`docker.elastic.co/elasticsearch/elasticsearch:8.15.3`.

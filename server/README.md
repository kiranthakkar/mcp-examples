# Server

## Getting started

### Create IDCS domain

### Prepare server

1. Install uv
2. Set environment variables:
```bash
export IDCS_CLIENT_ID=<value>
export IDCS_CLIENT_SECRET=<value>
# this isn't a URL 👇
export IDCS_DOMAIN="hostname:port"
```
2. Start the server
```bash
uv run server.py
```
3. Optional: set token (JWT retrieved from IDCS Oauth/OIDC);
copy it to clipboard and then:
```bash
export TOKEN=$(pbpaste)
```
4. Clear contents of clipboard (copy something else)
5. Run client
```bash
uv run client.py
```

# aegis-smcp-gateway

Standalone SMCP tooling gateway implementing ADR-053.

## Features

- Workflow-first macro tools (`ToolWorkflow`) backed by OpenAPI operation resolution
- SMCP envelope verification for invocation endpoint
- Control-plane CRUD for API specs, workflows, and ephemeral CLI tools
- API Explorer with JSONPath response slicing
- Ephemeral CLI invocation in Docker with semantic gating
- SQLite-first persistence for standalone deployment

## API

- `POST /v1/specs`
- `GET /v1/specs`
- `GET /v1/specs/{id}`
- `DELETE /v1/specs/{id}`
- `POST /v1/workflows`
- `GET /v1/workflows`
- `GET /v1/workflows/{id}`
- `PUT /v1/workflows/{id}`
- `DELETE /v1/workflows/{id}`
- `POST /v1/cli-tools`
- `GET /v1/cli-tools`
- `DELETE /v1/cli-tools/{name}`
- `POST /v1/smcp/sessions`
- `GET /v1/tools`
- `POST /v1/explorer`
- `POST /v1/invoke`

## Configuration

Environment variables:

- `SMCP_GATEWAY_BIND` (default: `0.0.0.0:8089`)
- `SMCP_GATEWAY_GRPC_BIND` (default: `0.0.0.0:50055`)
- `SMCP_GATEWAY_DB` (default: `sqlite://gateway.db`)
- `SMCP_GATEWAY_OPERATOR_JWT_PUBLIC_KEY_PEM` (required unless `SMCP_GATEWAY_AUTH_DISABLED=true`)
- `SMCP_GATEWAY_OPERATOR_JWT_ISSUER` (default: `aegis-keycloak`)
- `SMCP_GATEWAY_OPERATOR_JWT_AUDIENCE` (default: `aegis-smcp-gateway`)
- `SMCP_GATEWAY_SMCP_JWT_PUBLIC_KEY_PEM` (required)
- `SMCP_GATEWAY_SMCP_JWT_ISSUER` (default: `aegis-orchestrator`)
- `SMCP_GATEWAY_SMCP_JWT_AUDIENCE` (default: `aegis-agents`)
- `SMCP_GATEWAY_AUTH_DISABLED` (default: `false`)
- `SMCP_GATEWAY_SEMANTIC_JUDGE_URL` (optional; required when invoking CLI tools with `require_semantic_judge=true`)
- `SMCP_GATEWAY_NFS_HOST` (default: `127.0.0.1`)
- `SMCP_GATEWAY_NFS_PORT` (default: `2049`)
- `SMCP_GATEWAY_NFS_MOUNT_PORT` (default: `20048`)

## Run

```bash
cargo run
```

The binary serves:

- HTTP control/invocation API on `SMCP_GATEWAY_BIND`
- gRPC `ToolWorkflowService` + `GatewayInvocationService` on `SMCP_GATEWAY_GRPC_BIND`

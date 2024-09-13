# HTML API Example - OIDC Authentication

This example demonstrates how to log in users using OIDC and setup middleware to autneticate requests based on the *access_token*.

## Quick Start

1. **Set up an OIDC app** (e.g., Auth0 or any other OIDC provider that uses JWTs for acccess tokens) and get:
   - **Client ID** (set as `AUTH0_CLIENT_ID`)
   - **Client Secret** (set as `AUTH0_CLIENT_SECRET`)
   - **OIDC Discovery URL** (set as `AUTH0_OIDC_CONFIG`, usually ends with `/.well-known/openid-configuration`)

2. **Set environment variables**:
 ```bash
export AUTH0_CLIENT_ID=your_client_id
export AUTH0_CLIENT_SECRET=your_client_secret
export AUTH0_OIDC_CONFIG=your_oidc_discovery_url
```

3. **Run the app**:
```go
go run *.go
```

> **Note**: In a real production scenario, we wouldn't typically store access tokens in cookies like this. Since this is a traditional server-side app that renders HTML for the browser, we would usually store sessions on the server and use Secure, HTTP-only, encrypted cookies to store the session ID. This example is just for demonstration, though there are cases where token storage in cookies may be appropriate.

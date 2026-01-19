# OpenCertServer Web UI

Angular web interface for OpenCertServer Certificate Authority.

## Configuration

1. Copy `src/config.example.json` to `src/config.json`
2. Update the OIDC settings with your identity provider details:

```json
{
  "oidc": {
    "issuer": "https://your-identity-provider.com",
    "clientId": "your-client-id",
    "redirectUri": "http://localhost:4200",
    "postLogoutRedirectUri": "http://localhost:4200",
    "scope": "openid profile email",
    "responseType": "code",
    "requireHttps": false
  },
  "api": {
    "baseUrl": "http://localhost:5000/api"
  }
}
```

## Installation

```bash
npm install
```

## Development Server

```bash
npm start
```

Navigate to `http://localhost:4200/`. The application will automatically reload if you change any of the source files.

## Build

```bash
npm run build
```

The build artifacts will be stored in the `dist/` directory.

## Features

- OIDC Authentication with configurable identity provider
- Certificate Management and Viewing
- Advanced Certificate Filtering and Search
- Material UI with Blue Theme
- Responsive Design

# MFA backend

This repository contains the Node.js and Express backend for a multi-factor
authentication (MFA) exercise. It implements the server-side part of a TOTP
flow: user MFA data is stored in MongoDB, QR-code setup data is generated for
an authenticator app, and submitted one-time codes are verified before a JWT
is issued.

The application uses the existing [Metropolia Auth API](https://media2.edu.metropolia.fi/auth-api/)
for user authentication. If you are connecting from home, access to the Auth
API requires the Metropolia VPN.

The companion frontend is available in the
[MFA-client-starter repository](https://github.com/purkkapunkki/MFA-client-starter).

## Prerequisites

- Node.js and npm
- A MongoDB database for MFA data
- Access to the Metropolia Auth API

## Installation

Clone the repository and install its dependencies:

```bash
git clone https://github.com/purkkapunkki/MFA-starter.git
cd MFA-starter
npm install
```

Create a local environment file from the example:

```bash
cp .env.sample .env
```

On Windows PowerShell, use `Copy-Item .env.sample .env` instead.

Update `.env` with values for your local environment:

```dotenv
NODE_ENV=development
PORT=3000
DB_URL=mongodb://localhost:27017/2fa_db
AUTH_URL=https://media2.edu.metropolia.fi/auth-api/api/v1
JWT_SECRET=replace-with-a-local-secret
```

- `DB_URL` is the MongoDB connection string used to store MFA records.
- `AUTH_URL` points to the existing Auth API.
- `JWT_SECRET` is used to sign JWTs. Keep it private and do not commit `.env`.

## Run the backend

Start the development server with:

```bash
npm run dev
```

The API listens on `http://localhost:3000` by default. The frontend expects
the MFA endpoints under `http://localhost:3000/api/v1`.

## Other scripts

```bash
npm run build  # Compile TypeScript
npm test       # Run tests
npm run lint   # Lint and fix source and test files
```

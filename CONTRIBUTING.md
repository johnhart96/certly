# Contributing

Bug reports, ideas and pull requests are welcome.

## Development setup

You need Node.js 22 or later.

```sh
npm install
npm run dev        # restarts on file changes, data goes in ./data
npm test
```

Open <http://localhost:3000>. To start with a fresh CA, delete `./data`.

## Project layout

```
src/
  ca.js       root CA creation, CSR signing and key generation
  store.js    JSON metadata + PEM files on disk
  auth.js     OpenID Connect sign-in and signed session cookies
  app.js      Express routes (createApp)
  server.js   entrypoint: reads environment variables and listens
public/       the web UI (plain HTML, CSS and JS, no build step)
test/         node:test suites (mock-oidc.js is a stand-in identity provider)
```

## Pull requests

- Keep changes focused, and add or update tests in `test/` for behaviour changes.
- Make sure `npm test` passes and that `docker compose up --build` still starts.
- The frontend has no build step or framework, and should stay that way unless there's a strong reason.
- Changes that affect what Certly will sign, such as name checks, key usages or validity limits, need a clear explanation in the PR. They are security-sensitive.

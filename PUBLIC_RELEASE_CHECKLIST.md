# Public Release Checklist

Before publishing this repository publicly, manually verify each item below.

## Ownership and Employer IP

- [ ] Confirm the project was created personally and not as part of employer work.
- [ ] Confirm no employer source code, proprietary logic, architecture, internal
      documentation, tickets, diagrams, prompts, or copied snippets are included.
- [ ] Confirm no employer-specific comments, naming, package paths, namespaces,
      internal workflows, or test data remain.
- [ ] Confirm you have the right to publish every file in the repository.

## Secrets and Credentials

- [ ] Search for API keys, access tokens, OAuth secrets, passwords, private keys,
      certificates, signing keys, database URLs, webhook URLs, and session values.
- [ ] Review `.env`, local config files, shell history snippets, test fixtures,
      logs, generated artifacts, screenshots, and documentation examples.
- [ ] Confirm example credentials are clearly fake and cannot grant access to
      any real service.
- [ ] Consider running a dedicated scanner such as `gitleaks` or `trufflehog`
      before publishing.

## Internal URLs and Infrastructure

- [ ] Search for internal URLs, private hostnames, VPN-only domains, intranet
      links, private IP addresses, staging endpoints, and company service names.
- [ ] Confirm no telemetry endpoints, SIEM destinations, hostnames, usernames,
      filesystem paths, or organization names identify private infrastructure.

## Test Data and Documentation

- [ ] Confirm test data is synthetic, public, or otherwise safe to publish.
- [ ] Confirm documentation examples do not reveal private operating procedures,
      security rules, incident details, customer data, or employer-specific
      conventions.
- [ ] Confirm screenshots, logs, and generated outputs do not contain personal,
      employer, customer, or infrastructure information.

## Dependency and License Review

- [ ] Review direct and transitive dependency licenses for compatibility with
      Apache License 2.0 and public distribution.
- [ ] Confirm dependency notices or attribution requirements are satisfied.
- [ ] Confirm generated lockfiles are safe and intentional to publish.

## Repository Hygiene

- [ ] Confirm `LICENSE`, `NOTICE`, `README.md`, `SECURITY.md`,
      `CONTRIBUTING.md`, and `.gitignore` are present and accurate.
- [ ] Confirm build and test instructions work on a clean machine.
- [ ] Confirm no unnecessary build artifacts, caches, editor metadata, or local
      machine files are tracked.
- [ ] Confirm the default branch, repository description, topics, and visibility
      settings are ready for public release.

## Release Decision

- [ ] Decide whether to publish immediately or first create a private backup.
- [ ] Decide whether GitHub Issues, Discussions, Security Advisories, and pull
      requests should be enabled.
- [ ] Decide whether to tag an initial release such as `v0.1.0`.

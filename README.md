# API Authorization Profile

**A jurisdiction-neutral, two-tier, machine-checkable profile for securing APIs with OAuth 2.1 and FAPI 2.0.**

Spec home: [apicommons.org/api-authorization](https://apicommons.org/api-authorization) · Ruleset: [`@api-common/spectral-api-authorization-ruleset`](https://github.com/api-commons/spectral-api-authorization-ruleset) · Registered in [Ruleset Commons](https://rulesets.apicommons.org).

Most API programs assert "we use OAuth" and stop there. This profile says *which* OAuth — as a small set of requirements you can **check against the artifacts an API already publishes**, at two assurance tiers, so conformance is a CI lint instead of an annual review. It follows the **profile, don't invent** posture: every requirement grounds in an existing IETF or OpenID standard; this document only *composes and tiers* them. It was generalized from Germany's federal [*Föderale API-Autorisierungsinfrastruktur*](https://gitlab.opencode.de/sachsen-anhalt/mid/foederale-api-autorisierungsinfrastruktur) security profiles into a standard-neutral form any API program — public or private — can adopt. A jurisdiction-specific variant (e.g. a US-government profile keyed to FIPS-199 impact levels) layers on top of this; this document names no jurisdiction.

## Two tiers

| Tier | Grounded in | For |
|---|---|---|
| **`normal`** | [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) (OAuth 2.0 Security BCP) + [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) hardening | the default baseline for any API using OAuth |
| **`high`** | [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html), with `normal` as its floor | high-assurance, cross-boundary, or M2M-at-scale APIs |

`high` is a strict superset. An assertion names a tier: `conformsTo: https://apicommons.org/api-authorization/high`.

## Two lint targets

The posture lives in two artifacts, so conformance is checked against both:

- **Target A — OpenAPI** (3.x): security-scheme contract, global/operation `security`, declared scopes, transport, and the shape of OAuth flows (which lets us ban `implicit`/`password`).
- **Target B — OAuth 2.0 Authorization Server Metadata** ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414), `/.well-known/oauth-authorization-server` or `/.well-known/openid-configuration`): client-auth methods, DPoP/sender-constraining, PAR, PKCE, response types, the mix-up `iss` parameter, signing algorithms, endpoint discovery.

Many programs publish an OpenAPI but not their AS metadata; requirement **AZ-META-1** is that the AS metadata be published at all, precisely so Target B becomes checkable.

## Requirements

Each requirement: **ID · tier · target · keyword · grounding clause.** The machine-readable form is [`profile.json`](./profile.json); the executable form is the [ruleset](https://github.com/api-commons/spectral-api-authorization-ruleset). Keywords follow RFC 2119 / RFC 8174; severity maps MUST → `error`, SHOULD → `warn`.

### Transport
- **TLS-1** · normal · A,B · MUST — all endpoints (API servers, token/authorization/AS-metadata `issuer`, OAuth flow URLs) use `https`. *(RFC 9700 §2.6; OAuth 2.1 §1.7)*

### Grant & response types
- **GRANT-1** · normal · A,B · MUST NOT — the `implicit` grant / `token` response type is not offered. *(OAuth 2.1; RFC 9700 §2.1.2)*
- **GRANT-2** · normal · A,B · MUST NOT — the resource-owner `password` grant is not offered. *(OAuth 2.1; RFC 9700 §2.4)*
- **GRANT-3** · normal · A · MUST — OAuth2 flows are limited to `authorizationCode` and `clientCredentials`. *(OAuth 2.1 §1.3)*
- **RESP-1** · high · B · MUST — `response_types_supported` is `code` only. *(FAPI 2.0 §5.3)*
- **ISS-1** · high · B · MUST — authorization-response `iss` parameter is supported. *(RFC 9207; FAPI 2.0)*

### PKCE
- **PKCE-1** · normal · B · SHOULD — PKCE is supported. *(RFC 9700 §2.1.1; RFC 7636)*
- **PKCE-2** · high · B · MUST — PKCE with `S256` is supported. *(FAPI 2.0 §5.3)*

### Client authentication
- **CAUTH-1** · high · B · MUST — `private_key_jwt` or mTLS (`tls_client_auth`/`self_signed_tls_client_auth`). *(FAPI 2.0 §5.3; RFC 7523; RFC 8705)*
- **CAUTH-2** · high · B · MUST NOT — shared-secret client auth (`client_secret_*`) is not offered. *(FAPI 2.0 §5.3)*

### Sender-constraining
- **SC-1** · high · B · MUST — access tokens are sender-constrained via DPoP or mTLS; bearer-only is unacceptable at `high`. *(FAPI 2.0 §5.3; RFC 9449; RFC 8705)*
- **SC-2** · normal · B · SHOULD — sender-constraining is supported. *(RFC 9700 §2.2, §4.8)*

### Pushed Authorization Requests
- **PAR-1** · high · B · MUST — PAR is required and its endpoint advertised. *(FAPI 2.0 §5.3; RFC 9126)*
- **PAR-2** · normal · B · MAY — PAR is supported. *(RFC 9126)*

### Tokens & algorithms
- **ALG-1** · normal · B · MUST NOT — `none` signing algorithm is not offered. *(RFC 9700 §2.6; RFC 8725)*
- **ALG-2** · high · B · MUST — asymmetric signing only; no `HS*`. *(FAPI 2.0; RFC 8725)*
- **TOK-1** · normal · B · SHOULD — JWT access tokens follow RFC 9068 (`at+jwt`). *(RFC 9068)*

### Scopes & operation security *(OpenAPI-facing; complements OWASP API2/API8)*
- **SEC-1** · normal · A · MUST — every operation is covered by `security` (global or operation-level). *(RFC 9700 §2.3; OWASP API2)*
- **SEC-2** · normal · A · MUST — at least one OAuth2/OIDC security scheme is defined and referenced. *(OAuth 2.1)*
- **SCOPE-1** · normal · A · SHOULD — flows declare named scopes; operations request least-privilege scope(s). *(RFC 9700 §2.3)*

### Authorization-server discoverability
- **AZ-META-1** · normal · B · SHOULD — the AS publishes RFC 8414 metadata (enables every Target-B check). *(RFC 8414)*
- **AZ-META-2** · normal · B · SHOULD — revocation ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)) and introspection ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)) endpoints are advertised. *(dynamic revocation)*

## The floor — what this profile does NOT prove

Static conformance is **necessary, not sufficient**. It cannot verify that DPoP proofs are validated, that tokens are truly bound, that the PAR endpoint works, that revocation revokes, or that object-/function-level authorization is correct (that is [OWASP API1/API5](https://github.com/api-commons/spectral-owasp-ruleset)). A clean report means the *declared contract* is not leaving an obvious door open; the rest is owed to code, tests, and the running gateway. Advertising `require_pushed_authorization_requests: true` is proof the server *claims* to require PAR, not proof it enforces it.

## Tooling & conformance

- **Lint it:** [`@api-common/spectral-api-authorization-ruleset`](https://github.com/api-commons/spectral-api-authorization-ruleset) — two Spectral rule files (OpenAPI + AS-metadata), built-in functions only, with fixtures and a passing test harness.
- **Machine-readable profile:** [`profile.json`](./profile.json) — every requirement with its tier, target, keyword, grounding clause, and the rule id that enforces it.
- **Declare conformance:** an [APIs.json](https://apisjson.org) entry or an [API Onboarding Descriptor](https://apicommons.org/onboarding) can assert `securityProfile: { conformsTo, tier }`; the ruleset then checks the claim.

## Relationship to the rest of the suite

Complements the [OWASP ruleset](https://github.com/api-commons/spectral-owasp-ruleset) (which covers the security Top 10 broadly, including authorization *outcomes*); this profile covers the *authorization mechanism's* standards conformance at two tiers. Registered in [Ruleset Commons](https://rulesets.apicommons.org) as an adopt-by-reference entry. Referenced from the [API Onboarding Descriptor](https://apicommons.org/onboarding) via its `securityProfile` field.

## Provenance & versioning

`v0.1`. Every requirement carries its grounding clause above and in `profile.json`. Owner: API Commons. Source lineage: the German federal API authorization *Sicherheitsvorgaben* (RFC 9700 / FAPI 2.0), generalized. License: Apache-2.0.

## Part of API Commons

A machine-readable building block from **[API Commons](https://apicommons.org)** — open specifications and schemas for the APIs you produce and consume. See all building blocks and tools at **[apicommons.org](https://apicommons.org)** and the tools at **[apicommons.org/tools](https://apicommons.org/tools/)**.

**Related building blocks**
- [spectral-api-authorization-ruleset](https://github.com/api-commons/spectral-api-authorization-ruleset) — the executable Spectral ruleset that lints this profile at both tiers
- [api-onboarding](https://github.com/api-commons/api-onboarding) — the onboarding descriptor that references this profile via `securityProfile`
- [rules](https://github.com/api-commons/rules) — machine-readable governance rules across artifact types
- [policies](https://github.com/api-commons/policies) — the business rationale behind API governance rules

## License

The artifacts in this repository — the schemas, examples, and API descriptions — are
licensed **[CC BY-NC-SA 4.0](LICENSE)** (Attribution–NonCommercial–ShareAlike).

API Commons licenses **artifacts** under CC BY-NC-SA 4.0 and **code** under Apache-2.0.

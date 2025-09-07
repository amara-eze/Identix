# Identix (Minimal Verifiable Credential System)

## Overview

**Identix** is a minimal W3C-compatible verifiable credential (VC) system implemented in Clarity. It provides a decentralized mechanism for **credential issuance, verification, revocation, and subject management**, enabling trust between issuers, subjects, and verifiers.

This system ensures that credentials are **tamper-proof, verifiable, and revocable**, making it suitable for identity systems, certifications, access control, and compliance use cases.

## Features

* **Issuer Management**

  * Register trusted credential issuers.
  * Deactivate issuers when no longer valid.
* **Schema Management**

  * Create schemas defining credential structures and attributes.
* **Subject Registration**

  * Register subjects (holders of credentials).
* **Credential Lifecycle**

  * Issue verifiable credentials with optional expiry.
  * Revoke credentials when compromised or invalid.
  * Check credential validity and ownership.
* **Verification Process**

  * Verifiers can validate credentials against proofs.
  * Verification attempts are logged with metadata (verifier, timestamp, success).
* **Status Management**

  * Credentials can be `active`, `revoked`, or `expired`.
* **Compliance-Oriented**

  * Built with **W3C Verifiable Credentials principles** in mind.

## Data Structures

* **Issuers**: Store issuer details, controller, and status.
* **Schemas**: Define credential templates with attributes.
* **Subjects**: Represent credential holders with credential counts.
* **Credentials**: Store subject, issuer, schema, hash, expiration, and status.
* **Verifications**: Log verification attempts.

## Core Functions

### Issuer

* `register-issuer (id name)` – Register a new issuer.
* `deactivate-issuer (id)` – Deactivate an issuer.
* `is-issuer-active (id)` – Check if an issuer is active.

### Schema

* `create-schema (id name issuer-id attributes)` – Define a credential schema.
* `get-schema (id)` – Retrieve schema details.

### Subject

* `register-subject (id)` – Register a credential subject.
* `get-subject (id)` – Retrieve subject details.
* `get-subject-credential-count (id)` – Count subject credentials.

### Credential

* `issue-credential (id subject-id issuer-id schema-id hash expires-at)` – Issue a new credential.
* `revoke-credential (id)` – Revoke an existing credential.
* `verify-credential (id proof)` – Verify a credential and log the attempt.
* `check-credential-status (id)` – Get the credential’s status.
* `credential-belongs-to-subject (cred-id subj-id)` – Confirm subject ownership.

### Verification Logs

* `get-verification (id)` – Retrieve verification details.
* `get-verification-counter` – Track number of verifications.

### Metadata

* `get-contract-info` – Returns contract version and name.

## Error Codes

* `u400` – Invalid parameters.
* `u401` – Unauthorized action.
* `u404` – Not found.
* `u409` – Already exists.
* `u410` – Expired.
* `u411` – Revoked.
* `u412` – Inactive issuer.

## Example Workflow

1. **Register an issuer** with an ID and name.
2. **Create a schema** under the issuer to define credential structure.
3. **Register a subject** (credential holder).
4. **Issue a credential** for the subject using schema and credential hash.
5. **Verify credential** by providing proof.
6. If compromised, **revoke credential**.
7. Use read-only functions to **check status, retrieve details, and validate ownership**.

## Contract Info

* **Name:** Identix (Minimal VC System)
* **Version:** 1.0.0
* **Standard:** W3C-compatible Verifiable Credentials

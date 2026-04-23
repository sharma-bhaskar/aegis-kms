# Changelog

All notable changes to Aegis-KMS will be documented here. This project
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Repository scaffold: sbt multi-project layout, Apache-2.0 license, CI
  workflow, contribution and security policies.
- `aegis-core` module with typed domain ADTs (`Principal`, `KeyId`,
  `KeySpec`, `OperationResult`, `KeyService[F]`) and an in-memory reference
  implementation for smoke tests.

# Changelog

All notable changes to `@gethush/hush-crypto` (the Hush MLS / crypto WASM
package) are recorded here. Format is based on
[Keep a Changelog](https://keepachangelog.com). Versions track the `Cargo.toml`
package version, published to npm as `@gethush/hush-crypto`.

Each released version below must have a matching `## [version]` section: the
publish workflow extracts it as the GitHub Release body and fails the release if
it is missing.

## [Unreleased]

## [0.2.2] - 2026-05-11

### Changed
- MLS default ciphersuite switched to the X-Wing hybrid post-quantum KEM.

## [0.2.1] - 2026-03-31

### Changed
- npm package scope changed to `@gethush` (published as `@gethush/hush-crypto`).

## [0.2.0] - 2026-03-31

### Added
- Initial published WASM build of the Hush MLS / crypto package (voice frame-key
  and metadata-key exporters, MLS group operations), with CI and the npm publish
  workflow.

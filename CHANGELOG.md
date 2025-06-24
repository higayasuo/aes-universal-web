# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.10] - 2025-06-25

### Changed

- Updated peer dependencies:
  - `aes-universal` to v0.1.10
  - `aes-universal-node` to v0.1.10

## [0.1.9] - 2025-06-09

### Changed

- Updated peer dependencies:
  - `aes-universal` to v0.1.9
  - `aes-universal-node` to v0.1.9

## [0.1.8] - 2025-06-08

### Added

- Added `WebAesCipher` class that provides a unified interface for both CBC and GCM modes

## [0.1.7] - 2025-06-04

### Changed

- Changed the signature of `generateTag` in `WebCbcCipher` (now uses `keyBitLength` instead of `keyBits`)

## [0.1.6] - 2025-06-02

### Changed

- Renamed library to `aes-universal-web`
- Updated API to use `webCryptoModule` instead of `WebCryptoModule` class
- Changed cipher initialization to use `getRandomBytes` function directly

## [0.1.2] - 2025-04-18

### Added

- Initial release
- Separated web-specific implementation from `expo-aes-universal`
- Added Web Crypto API implementation for AES encryption
- Added test cases for Web implementation
- Added documentation for web-specific usage

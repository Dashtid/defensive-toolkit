# Changelog

## [1.3.0](https://github.com/Dashtid/defensive-toolkit/compare/v1.2.0...v1.3.0) (2026-01-22)


### Features

* Add comprehensive Linux hardening and testing suite (v1.2.0) ([9380b3c](https://github.com/Dashtid/defensive-toolkit/commit/9380b3cbb625c47e0eb2c51065bfcd86336afabb))
* add Helm chart, webhook retry service, and auth documentation ([5ece562](https://github.com/Dashtid/defensive-toolkit/commit/5ece56277932e9246535165a66799b61f20a50f4))
* **api:** add enhanced health checks, delivery tests, and docs update ([f376f95](https://github.com/Dashtid/defensive-toolkit/commit/f376f95d4189b0cc41eddfb69b85f9d77af1f11d))
* **api:** add webhook tests, Prometheus metrics, and input validation ([20fecdf](https://github.com/Dashtid/defensive-toolkit/commit/20fecdf3f9771d2b026135e8739f7c0fdd3ca85e))
* **api:** enhance rate limiting with Redis and per-user support ([7377490](https://github.com/Dashtid/defensive-toolkit/commit/7377490b62cfb3efe67cd94879827809f3ac5e5c))
* **api:** wire up all routers and add hardening module (v1.7.0) ([a82a512](https://github.com/Dashtid/defensive-toolkit/commit/a82a512afd404e4d1b7f793cb91de588e8b1c209))
* **ci:** add container image signing with Cosign ([4209fbf](https://github.com/Dashtid/defensive-toolkit/commit/4209fbf98e85f803462b300dec07cd1811f65a1b))
* **ci:** add pip-audit and gitleaks security scanning ([1eaeee8](https://github.com/Dashtid/defensive-toolkit/commit/1eaeee877bd31fc5f5808e2d418b4ffcb3e77d96))
* **ci:** add release automation with Release Please ([2c4b29d](https://github.com/Dashtid/defensive-toolkit/commit/2c4b29dd7aa6c998eb21d158059e4fc46ecff535))
* **ci:** add Semgrep SAST, SBOM generation, and Kubernetes manifests ([9c0bd97](https://github.com/Dashtid/defensive-toolkit/commit/9c0bd977d2b4355560b6b7a3c08bc353b1165519))
* Complete defensive-toolkit with compliance and log analysis (10/10 categories) ([c48ff29](https://github.com/Dashtid/defensive-toolkit/commit/c48ff2963e52c7fb5464e905553dee74d8037cb7))
* **hardening:** add Windows CIS Benchmark scanner with 17 security checks ([12759b6](https://github.com/Dashtid/defensive-toolkit/commit/12759b62c9d59dcb6aeb9dd07ea82b58236db3a2))
* Implement comprehensive digital forensics toolkit ([16f7f7a](https://github.com/Dashtid/defensive-toolkit/commit/16f7f7a8b7c5d32bf204a8c6558020af549b5d0b))
* Implement comprehensive vulnerability management system ([d8c6e66](https://github.com/Dashtid/defensive-toolkit/commit/d8c6e664f471c80cb76b9dc3a0cd4a073353ff0d))
* Implement security automation and orchestration (SOAR) framework ([2c7c461](https://github.com/Dashtid/defensive-toolkit/commit/2c7c46114b8a0a30b2b9bdb4da528bbdaa28d0e3))
* **rust:** add high-performance Rust log parser with PyO3 bindings ([76d6b49](https://github.com/Dashtid/defensive-toolkit/commit/76d6b494576f221b0cd47247a476cd0d7d9aed56))


### Bug Fixes

* Add missing API dependencies (FastAPI, pydantic, etc.) ([0f4d300](https://github.com/Dashtid/defensive-toolkit/commit/0f4d300b5744958d3224a28d8fd771e81efbcf4f))
* add prometheus-fastapi-instrumentator dependency ([637a10a](https://github.com/Dashtid/defensive-toolkit/commit/637a10a274bcabd5cb30d8a2c514d3f234ac03bc))
* add skip markers for CI-incompatible tests ([0958163](https://github.com/Dashtid/defensive-toolkit/commit/09581637df2b5178b02365d1afdc10c16ae79d87))
* **ci:** add explicit target: runtime to build-push-action ([6932353](https://github.com/Dashtid/defensive-toolkit/commit/6932353833f8afc1793ee18f0a5d22f2659e33d8))
* **ci:** Apply Black formatting and fix Docker workflow permissions ([c92ce50](https://github.com/Dashtid/defensive-toolkit/commit/c92ce50497e128f2eef86f8ed8a4db5ef874d536))
* **ci:** don't fail Docker build on Trivy vulnerabilities ([ad1f0f6](https://github.com/Dashtid/defensive-toolkit/commit/ad1f0f6114ab1d969f73ba65fddc1bf6cb39a1c2))
* **ci:** force --no-build flag to use pre-built images in container tests ([ec9c909](https://github.com/Dashtid/defensive-toolkit/commit/ec9c909556869b5e01d941e51a118ea1eb684a32))
* **ci:** Install Windows-only extras only on Windows runners ([2914d76](https://github.com/Dashtid/defensive-toolkit/commit/2914d760053a0620a1c3a1219bc8729da2eb800e))
* **ci:** Relax CI workflows to not fail on warnings ([1dfb98a](https://github.com/Dashtid/defensive-toolkit/commit/1dfb98a7090aaf935a089a3b442911343324b82b))
* **ci:** replace forward slashes in Docker artifact names ([f072942](https://github.com/Dashtid/defensive-toolkit/commit/f07294230a607c4597b6a3c12ba6bea0f5158a28))
* **ci:** tag loaded Docker images for Trivy scanning ([93ca04f](https://github.com/Dashtid/defensive-toolkit/commit/93ca04f32a765e60ab0a6b3b841b49ece487ce51))
* **ci:** Update CI workflows and linting configuration for passing builds ([d09180a](https://github.com/Dashtid/defensive-toolkit/commit/d09180a615ad78b9d3fc456425910ddc6a10fe62))
* **ci:** use pre-built Docker images in container tests ([04cc27f](https://github.com/Dashtid/defensive-toolkit/commit/04cc27fb70e3d0e7733dc712f351c0e1c1356fee))
* Copy README.md and skip project install in Docker build ([eb8580b](https://github.com/Dashtid/defensive-toolkit/commit/eb8580b9f594ec085f36bcaf3b7efd47c3f716ba))
* **docker:** correct relative paths in docker-compose.yml ([f2be1df](https://github.com/Dashtid/defensive-toolkit/commit/f2be1dfe83bc9febcabd1c6e15d8f239528329a2))
* **docker:** set UV_PROJECT_ENVIRONMENT to ensure deps in correct venv ([1cdbdc8](https://github.com/Dashtid/defensive-toolkit/commit/1cdbdc80da1b586420e98757134d29921dbdd317))
* Exclude Windows-only extras from Docker build ([fae13fb](https://github.com/Dashtid/defensive-toolkit/commit/fae13fb47ff86095191fc9ded6cb638a4758dc43))
* Fix Black formatting and skip flaky virustotal test ([a93a995](https://github.com/Dashtid/defensive-toolkit/commit/a93a99597bf5035199c8ba5e96315dd6d203c02f))
* Fix import sorting and add python-multipart dependency ([6bd0acf](https://github.com/Dashtid/defensive-toolkit/commit/6bd0acf2b200f35f9b8affc125e447a67bd8911a))
* Fix workflow validation and Black formatting ([7b62cd3](https://github.com/Dashtid/defensive-toolkit/commit/7b62cd3bcffdd7b2313815e0b8770905908136d2))
* Fix YARA syntax errors and add skip markers for bash-dependent tests ([ac184e0](https://github.com/Dashtid/defensive-toolkit/commit/ac184e093800e7f8c185d1c571705f94c77fc95f))
* Match Black formatting for HARDENING_DIR paths ([819c0ac](https://github.com/Dashtid/defensive-toolkit/commit/819c0ac058cded12ab274697fe8d595c5eaacffb))
* Rename Python files from kebab-case to snake_case ([7237431](https://github.com/Dashtid/defensive-toolkit/commit/723743115b78c53133cc26b051b0f6c34ebf5311))
* resolve monitoring service test and auth import paths ([291c1b4](https://github.com/Dashtid/defensive-toolkit/commit/291c1b471c7f5fd636e1aad17448579f715665d0))
* resolve remaining CI failures ([9355ac1](https://github.com/Dashtid/defensive-toolkit/commit/9355ac109601482d389ec348014fc0903b11b424))
* Resolve remaining CI failures ([47290d1](https://github.com/Dashtid/defensive-toolkit/commit/47290d14afad7b7d125b7a3cfeb8406ef52dbcaf))
* **security:** remediate eval, shell injection, BOLA, SSRF, and XXE vulnerabilities ([5a81658](https://github.com/Dashtid/defensive-toolkit/commit/5a81658b4d66bfcfe0aa95cdab37ec453ca78970))
* **tests:** Fix test/implementation mismatches ([dde1587](https://github.com/Dashtid/defensive-toolkit/commit/dde1587f7214e1559296662af4f1e2a825b944bd))
* **tests:** Update test imports for new src/defensive_toolkit layout ([9add06e](https://github.com/Dashtid/defensive-toolkit/commit/9add06e1b4bc9b7ec0ce6e9d3e3934559f673194))
* update all API imports to defensive_toolkit.api path ([6b7747c](https://github.com/Dashtid/defensive-toolkit/commit/6b7747c9a8243e6f2d48fb442b27dbe2d160f005))
* update imports and Dockerfile for src layout ([b351a61](https://github.com/Dashtid/defensive-toolkit/commit/b351a61f959186661802155bf66a272761288514))
* update test paths and add skip markers for unimplemented methods ([35e1148](https://github.com/Dashtid/defensive-toolkit/commit/35e1148d82eb9d6740a971f5d535fac2942b619f))
* use docker compose v2 command in CI workflow ([ca0b72d](https://github.com/Dashtid/defensive-toolkit/commit/ca0b72db8cf36c0f279d5d21a596af0c14437a54))


### Code Refactoring

* Major repository restructure for professional organization ([8a5deb6](https://github.com/Dashtid/defensive-toolkit/commit/8a5deb65e79c4f92d04837948e577ffa14724c73))


### Documentation

* add CHANGELOG v1.2.0 entries and Helm example values ([ddf2e4c](https://github.com/Dashtid/defensive-toolkit/commit/ddf2e4c496505dfa27dac5f2bdf31d0aedaffe66))
* Update all documentation to reflect project completion ([f28e49b](https://github.com/Dashtid/defensive-toolkit/commit/f28e49b0f6f5662837df312fdba9acce1b8fe49c))


### Tests

* **api:** add comprehensive router tests and fix package structure ([aa4762e](https://github.com/Dashtid/defensive-toolkit/commit/aa4762ed970c8413f471242c801a2c23def6154e))
* **api:** fix 136 pre-existing test failures and add vulnerability tests ([1bdb195](https://github.com/Dashtid/defensive-toolkit/commit/1bdb19513e325045ee437d7643e2b6e5024c02d2))
* **api:** fix auth fixtures in test_assets.py and test_incident_response.py ([dfd7d47](https://github.com/Dashtid/defensive-toolkit/commit/dfd7d47973944c7aceddd6171a990c6419b9ecaf))
* **api:** improve vulnerability and compliance router coverage to 80%+ ([1e02b15](https://github.com/Dashtid/defensive-toolkit/commit/1e02b1538a62b61d7edefe3eab7078a3a944b33d))
* skip API integration tests requiring auth middleware ([e5c5ee9](https://github.com/Dashtid/defensive-toolkit/commit/e5c5ee9d6fe40128cc5e7cd3fd87e511d2cc3d76))


### CI/CD

* add dependabot, CODEOWNERS, pre-commit hooks, and fix route ordering ([049ecf7](https://github.com/Dashtid/defensive-toolkit/commit/049ecf70a1cfdee8994044563369b5a39f8f4419))

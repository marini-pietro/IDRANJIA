# Contributing to IDRANJIA

Thank you for considering contributing. This file contains high-level contribution guidelines and expectations.  
Please note that this backend is intended to be used in conjunction with a separate [frontend repository](https://github.com/campionl/idranti-sicuri_frontend); while the backend can run and serve data independently, it is designed to be coupled with the project's frontend implementation.  
Please keep in mind that, because this codebase processes sensitive data and is subject to strict operational and privacy constraints, most external contributions are unlikely to be accepted.

Scope

- Code changes: add features, fix bugs, or improve tests and documentation.
- Tests: any code change that affects behavior should be accompanied by tests (using pytest) the moment the code change is proposed in a PR.
- Security: when changing authentication, authorization, password handling, or token logic, include a short rationale and tests that demonstrate safe behavior.
  For security related code changes make as many commits as possible, to facilitate and speed up potential rollback.

Guidelines

- Follow existing project structure and naming conventions, especially in `api_blueprints/`.
- Add unit tests for new behaviors in `tests/` and ensure existing tests keep passing.
- Keep secrets out of the repository (placeholder secrets can be left hardcoded but have to be clearly documents as such).  
  Make sure to not add credentials, private keys, or tokens to commits.

Review process

- Open a pull request describing the change, the reasoning, and test coverage.
- Ensure the PR includes updated or new tests and references any relevant issue addressed in the commits part of the PR.

Testing

- Tests are pytest-based and can be found in the `tests/` tree.  
  Focus on small, isolated tests for blueprints and logic particularly for sensitive sections such as the authorization flow and input validation.
- Make sure to respect the naming convention already put in place and to document all relevant tests with extensive comments and, ideally, a docstring.

Security sensitive changes

- For changes to authentication, password verification, token creation/validation, and input sanitization, include a brief security note in the PR describing the change, why it is safe and why the new solutions is better than the previous one.

Contact

- If you need help or want to discuss a larger design change: open an issue adding the proper details (such as your hardware configuration) in the repository Github page.

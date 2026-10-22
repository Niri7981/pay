# Contributing

Pay is developed in public and we appreciate contributions.

## Important: Branch Targeting

The `main` branch is the integration branch. All feature work and bug fixes should target `main`.

### Prerequisites

- [Just](https://github.com/casey/just) (command runner)
- Rust 1.86+
- Solana CLI 2.2+
- Node.js 20+ and pnpm (for SDK)

## Getting Started

Install all dependencies:

```shell
just install
```

## Rust CLI

```shell
just rs build              # Build release binary
just rs lint               # Clippy (warnings = errors)
just rs fmt                # Format check
just rs test               # Run all tests
just rs unit-test          # Unit tests only
just rs integration-test   # Integration tests only
just rs run -- --help      # Run the CLI
```

## TypeScript SDK

```shell
just ts install            # Install pnpm dependencies
just ts build              # Build the core package
just ts lint               # Check lint + formatting
just ts fmt                # Auto-fix formatting + lint
just ts typecheck          # Typecheck
just ts test               # Run tests
just ts test-watch         # Run tests in watch mode
```

## Correctness by construction

Payment code fails open in subtle ways: a check at one call site gets skipped by a sibling path, a second replica, a later refactor, or another SDK. Fix the class, not the instance:

- **Make invalid states unrepresentable.** Validate once at the boundary into a newtype with a private constructor (parse, don't validate). Prefer enums to bool/`Option` flags. No `Default` for security-relevant config.
- **Make required steps unskippable.** If B must follow check A, have A return a value (guard, token, proof) that B takes as an argument: a lock guard to write a journal, a reservation token to commit, a "not landed" proof to replace a transaction.
- **Put atomicity in the contract.** Check-and-reserve belongs inside one storage operation, not in callers. Every implementation of a storage trait runs the same shared test suite.
- **Cover every exit path.** Metering, settlement and cleanup that must happen run from a guard/`Drop` or a spawned task that a cancelled request cannot drop.
- **Enforce, don't document.** Prefer a compile error, then a test that fails in default CI, then a comment.
- **Pin behaviour across crates.** When pay relies on a pay-kit invariant, add a test on the pay side too, so a pay-kit bump that weakens it fails here.

## Before Submitting

- Run `just ci` (full lint, typecheck, test, build for both Rust and TypeScript)
- Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, etc.)
- Behavioural fixes ship with a regression test that fails before the change, plus a positive control.

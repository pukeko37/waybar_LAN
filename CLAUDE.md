# Rust Coding Policy

## Immutability

- **Default to immutable**: All variables `let`, never `let mut` without justification
- **Mutable variables are HUMAN-GATED**: Request approval with reason before using `mut`
- **Exception**: Local loop accumulators in private functions (< 10 lines scope)
- Prefer functional transformations over mutation

## Functional Programming Mandates

- Use `map`, `filter`, `fold`, `collect` over explicit loops
- Prefer `match` over nested `if/else` for all enums, `Option`, `Result`, multi-condition logic
- Functions return expressions, minimize side effects
- No `let mut` without human approval

## Type System Requirements

- **Value objects mandatory**: Wrap primitives with semantic types (e.g., `UserId(u64)`, not `u64`)
- **ZSTs for state machines**: Use `PhantomData<State>` to enforce state transitions at compile time
- **Const generics**: Use for fixed-size constraints when applicable
- **No trait objects (`dyn Trait`)** without human approval - prefer enums or generics
- Make illegal states unrepresentable

## Test-Driven Development (Red-Green-Refactor-Integrate)

0. **Search**: Check std → existing deps → search crates.io → get human approval for new deps
1. **Red**: Write failing unit test
2. **Green**: Minimal implementation to pass
3. **Refactor**: Clean up while maintaining green tests
4. **Integrate**: Add integration test only if needed (I/O, external boundaries)

### Unit Test Constraints

- No I/O, network, database, time dependencies
- Pure functions, fast (< 1s total suite)
- No mocking frameworks (indicates integration test)

### Integration Tests

- Live in `tests/` directory
- Not part of red-green cycle
- Only for critical boundaries, YAGNI applies

### Bug Fixes

- Write failing test → Fix → Verify test passes

## Library-First Policy

### Before writing non-trivial code (>50 lines)

1. Check if std library provides it
2. Check existing project dependencies
3. Search crates.io via MCP
4. Present options to human with downloads, maintenance status, size, trade-offs
5. **Human decides** on new dependencies

### Dependency Criteria

- >10k downloads, updated within 6 months
- Focused purpose (not kitchen-sink frameworks)
- Minimal transitive deps
- Use feature flags to minimize bloat: `default-features = false`

### Reject

- <1k downloads, >1 year unmaintained, >20 transitive deps, nightly-only

## Code Quality Gates (Self-Review Before Presenting)

```
□ Zero compiler warnings
□ Zero clippy warnings
□ All tests pass
□ No unwrap()/expect() without safety comment
□ Error paths tested
□ No TODO/FIXME committed
□ No dead code
□ Module < 1000 lines
```

## Error Handling

- Return `Result<T, E>` for all fallible operations
- Never `unwrap()` in library code; only in tests or with safety comment justifying why panic is impossible
- Use `?` operator, not manual unwrapping
- Errors must include context, be actionable

## Complexity Limits

- Max function: 50 lines
- Max cyclomatic complexity: 10 branches
- Max parameters: 4 (use structs if more needed)
- Max module: 500 lines (review needed), 1000 lines (MUST refactor)

**Check sizes**: `find src -name "*.rs" -exec wc -l {} \; | sort -rn | head -10`

## Module Organization

### Separate abstractions from implementation

- Traits, structs, enums, ZSTs → `domain/` or `types.rs`
- Business logic → `services/` or `impl.rs`
- I/O, external systems → `infrastructure/`

### State handling

Generic types parameterized by state:

```rust
struct Entity<State> { _state: PhantomData<State> }
struct Draft;
struct Published;
impl Entity<Draft> { fn publish(self) -> Entity<Published> }
```

### Cohesion & coupling

High cohesion within modules, low coupling between modules

---

## Waybar Widget Architecture

### Three-Layer Pattern

Waybar widgets follow a strict three-layer architecture:

- **Domain layer** (`domain/`): Validated types, pure business logic, no I/O
- **Data layer** (`api/` or `data/`): External data sources (APIs, system state, files)
- **Display layer** (`display/`): Waybar JSON formatting only

**Dependencies flow inward**: Display → Domain ← Data

**Data flow**: CLI args → Data source → Domain validation → Formatter → JSON stdout

### Domain Model Principles

Domain types enforce invariants at compile time:

- **Wrap all primitives** in semantic newtypes (never use raw `i32`, `String`, etc.)
- **Validation at construction**: Use `RangeValidated<T, R>` trait pattern for numeric bounds
- **Make illegal states unrepresentable**: Type system prevents invalid data
- **Zero-cost abstractions**: Use `PhantomData` for marker types
- **Separate data DTOs from domain types**: Data layer has its own models, converts to domain

**Why**: Type safety prevents runtime errors. Validation centralized in constructors. Data source changes (API updates, different system APIs) don't affect domain logic.

**Example**:
```rust
// Range validation with phantom types
pub struct TempRange;
impl RangeValidated<i32> for TempRange {
    const MIN: i32 = -40;
    const MAX: i32 = 55;
}
pub type Temperature = RangeValidatedValue<i32, TempRange>;
```

### Waybar Output Contract

Waybar widgets **must never panic** - always output valid JSON:

- **Success**: `{ "text": "displayed text", "tooltip": "hover details", "class": "css-class" }`
- **Error**: Degraded output with explanation in tooltip
- **Main returns `Ok(())`**: Handle all errors internally, format as JSON

**Error handling pattern**:
```rust
match client.fetch_data().await {
    Ok(data) => {
        let output = formatter.format(&data)?;
        println!("{}", serde_json::to_string(&output)?);
    }
    Err(e) => {
        let error_output = Formatter::create_error_output(&location, e);
        println!("{}", serde_json::to_string(&error_output)?);
    }
}
```

### Module Structure

Standard module layout for all waybar widgets:

- **`main.rs`**: CLI argument parsing, orchestration, error handling - **no business logic**
- **`domain/types.rs`**: Value objects with validation, calculations - **pure functions, no I/O**
- **`api/` or `data/`**: Data source (external API client, `/proc` readers, system calls)
  - `client.rs` or `collector.rs`: Fetch data
  - `models.rs`: DTOs that match external format (API JSON, `/proc` format, etc.)
- **`display/waybar.rs`**: Format domain models as Waybar JSON (text + tooltip + class)

---

## Security & Safety

- No hardcoded secrets (API keys, passwords, tokens)
- Use environment variables + `.gitignore` config files
- Type-wrap sensitive data: `struct ApiKey(String)`
- Verify APIs exist via `cargo doc` before using
- Run `cargo audit` with new dependencies
- No `unsafe` without human approval

## Change Management

- Max 20 message lines per commit
- One logical change per PR
- Doc comments (`///`) on all public items, explain **why** not what
- Commit messages: "Problem → Decision → Trade-off"; No advertising, e.g. "Generated with Claude Code" messages; 

## AI Decision Boundaries

### AI can decide

Implementation details, variable names, code organization within module, refactoring that preserves API

### Human decides

Public API design, architecture, breaking changes, new dependencies, trait objects, mutable variables, `unsafe` code

## Documentation Requirements

- Public APIs: Rustdoc with examples
- Non-obvious designs: Comment explaining approach and trade-offs
- Complex functions (>10 lines): Doc comment explaining why

## Build & CI

- `#![deny(warnings)]` in CI
- `cargo clippy -- -D warnings` pre-commit
- `cargo test --doc` (examples must compile)
- `cargo audit` before accepting dependency changes

### Nix Flake Deployment

Waybar widgets are deployed as Nix flakes to GitHub for reproducible builds:

- **`flake.nix`**: Define package with `rustPlatform.buildRustPackage`
- **`Cargo.lock`**: Must be committed - referenced by `cargoLock.lockFile`
- **Version**: Update in both `Cargo.toml` and `flake.nix` (keep in sync)
- **Metadata**: Set `description`, `license`, `platforms = platforms.linux`
- **Test flake build**: `nix build` before committing
- **Git clean**: Flakes only include tracked files - commit before building
- **Dev shell**: Include `rust-analyzer`, `rustfmt`, `clippy` for development

## YAGNI Enforcement

- Remove all unused code flagged by compiler warnings
- No "might be useful someday" code or dependencies
- No TODO tickets, create proper issues
- Boy scout rule: Leave code cleaner than found

---

## Workflow Summary

Before coding → State plan → Get human approval for: new deps, trait objects, mutable variables, breaking changes → Code with self-review checklist → Present clean result

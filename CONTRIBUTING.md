# Contributing to Chronicle

## Commit Convention

Chronicle follows the **Conventional Commits** format:

```text
type(scope): description
```

### Commit Types

| Type       | Use                          |
| ---------- | ---------------------------- |
| `feat`     | New feature                  |
| `fix`      | Bug fix                      |
| `refactor` | Code restructuring           |
| `perf`     | Performance improvement      |
| `test`     | Tests                        |
| `docs`     | Documentation                |
| `build`    | Build/dependencies/packaging |
| `ci`       | CI/CD changes                |
| `security` | Security-related changes     |
| `model`    | ML model changes             |
| `research` | Research/experiments         |
| `chore`    | General maintenance          |

### Examples

```text
feat(ebpf): add process monitoring
fix(database): prevent duplicate events
refactor(features): simplify feature extraction
perf(database): optimize history queries
test(detection): add anomaly detection tests
docs(readme): update installation guide
build(packaging): add Debian package
ci: add automated tests
security(api): restrict privileged endpoints
model(detection): add historical features
research: add baseline comparison
chore: update project configuration
```

### Guidelines

- Use lowercase types and scopes.
- Write descriptions in the imperative form.
- Keep commits focused on one logical change.
- Keep commit messages short and specific.
- Do not commit secrets, credentials, datasets, or local telemetry.

### Branch Naming

```text
feat/<description>
fix/<description>
refactor/<description>
research/<description>
docs/<description>
```

Example:

```text
feat/historical-profiling
fix/telemetry-collector
research/model-comparison
```

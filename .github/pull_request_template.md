# Pull request

## Summary

<What changed and why, in a few lines.>

## Jira

`FREES-<n>`

## ADR

<Link, or "not required: reason".>

## Type of change

- [ ] feat  - [ ] fix  - [ ] docs  - [ ] ci  - [ ] refactor  - [ ] test  - [ ] chore

## Testing

<Commands run and results; link to CI run.>

## Documentation

<Pages changed in this pull request, or "none: reason".>

## Security considerations

<Trust boundaries touched; security-review verdict link, or "not triggered: reason".>

## Checklist

- [ ] Branch is `<type>/FREES-<n>-<slug>` and rebased on latest `main`
- [ ] Title is a Conventional Commit with the FREES reference
- [ ] Containerfile rules respected (digest-pinned base, non-root); YAML starts with `---`
- [ ] No inline comments, secrets or unpinned references
- [ ] Tests and docs updated; required CI is green
- [ ] Reviewer is not the author

# Submodule contract

This toolkit is consumed as the `precogly-federal-toolkit` git submodule,
mounted at `vendor/precogly-federal-toolkit/` in the parent repository.

## How content gets here

The parent repository generates this tree from an allowlist manifest. Nothing
here is hand-edited:

```bash
# In the parent repository:
make oss-sync     # regenerate this tree from data/oss-split-manifest.yaml
make oss-check    # CI gate: fails if the tree is stale or carries private markers
```

`oss-sync` writes into the submodule's **working tree**. It does not commit,
push, or advance the parent's pin — each of those is a separate, reviewed step:

```bash
# 1. Review exactly what the projection changed.
make oss-submodule-status
git -C vendor/precogly-federal-toolkit diff

# 2. Commit and push inside the submodule, through its own review process.
git -C vendor/precogly-federal-toolkit switch -c <branch>
git -C vendor/precogly-federal-toolkit commit -am "<message>"
git -C vendor/precogly-federal-toolkit push -u origin <branch>
#    …then open a pull request against the toolkit's main.

# 3. Only after that merges, advance the parent's pin as its own commit.
git -C vendor/precogly-federal-toolkit switch main
git -C vendor/precogly-federal-toolkit pull --ff-only
git add vendor/precogly-federal-toolkit
git commit -m "chore(vendor): advance the toolkit pin to <sha>"
```

Keeping those three steps apart is deliberate. A regenerated projection is a
proposal, not an approved publication: the parent's redaction gate and the
toolkit's own `ci.yml` redaction job both have to pass, and the pin advance is
the record of a human having accepted the result.

## Consuming it from a private system repository

A system repository pins this toolkit and supplies its own system content:

```bash
git submodule add https://github.com/GSA-TTS/precogly-federal-toolkit.git \
  vendor/precogly-federal-toolkit
git submodule update --init vendor/precogly-federal-toolkit
```

Then call the toolkit's scripts rather than copying them. See
`templates/private-system-repository/README.md` for the expected layout and
`README.md` for the boundary grammar — the library tools here have no default
system inputs, by design.

## Wrapper targets

The parent `Makefile` keeps `oss-sync` and `oss-check` as CI gates. Add any
system-specific wrapper targets that call into
`vendor/precogly-federal-toolkit/` scripts rather than copying files by hand.

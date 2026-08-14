# Future submodule contract

This path (`oss/precogly-federal-toolkit/`) is the intended mount point for the
future `precogly-federal-toolkit` submodule. Until the external repository
exists, this checked-in directory is synchronized from local reusable sources.

## Conversion workflow

```bash
# Step 1 — Initialise a git repo inside the generated directory
#   (run this once, from the parent repo root)
make oss-submodule-init

# Step 2 — Push to a new remote (GitHub, etc.)
git -C oss/precogly-federal-toolkit remote add origin <url>
git -C oss/precogly-federal-toolkit push -u origin main

# Step 3 — Replace the checked-in directory with a real submodule
#   This removes the directory from the parent index and registers the submodule.
make oss-submodule-convert REMOTE=<url>

# Step 4 — Commit the submodule registration
git add .gitmodules oss/precogly-federal-toolkit
git commit -m "chore(oss): convert toolkit directory to git submodule"
```

## Ongoing sync

Until the submodule exists, keep the checked-in copy current with:

```bash
make oss-sync     # regenerate oss/ from data/oss-split-manifest.yaml
make oss-check    # CI gate: fails if oss/ is stale or contains private markers
```

## Wrapper targets

After submodule conversion the parent `Makefile` keeps `oss-sync` and
`oss-check` as CI gates. Add any system-specific wrapper targets that call
into `oss/precogly-federal-toolkit/` scripts rather than copying files by hand.

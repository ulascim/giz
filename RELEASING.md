# Releasing giz

Cut, sign, pin, and publish a new version of `giz`. The shipping
chain has three artifacts that must agree:

1. A GPG-signed git tag (`vX.Y.Z`) on a specific commit.
2. The source tarball at
   `https://github.com/ulascim/giz/archive/refs/tags/vX.Y.Z.tar.gz`,
   whose SHA-256 must match the `SOURCE_SHA` constant in `install.sh`
   and `install.ps1`.
3. The pinned `briar-headless-<os>-<arch>.jar` files attached to the
   GitHub Release `vX.Y.Z`, whose SHA-256s must match the `JAR_SHA_*`
   constants in the installers.

If any of these three desync, the installer aborts.

## One-time setup

Configure git to sign tags with your published GPG key:

```bash
git config --global user.signingkey <KEYID>
git config --global tag.gpgSign true
```

The same `<KEYID>` must be discoverable on a public keyserver under
the maintainer's identity (e.g. `keys.openpgp.org`). The key
fingerprint is what auditors will check before trusting a tag
signature.

## Cutting a release

Working tree must be clean and on `main`. Replace `0.1.1` below with
the new version.

```bash
# 1. land all release-candidate code on main and push
git pull --ff-only
git status                       # must be clean
./scripts/regenerate_lockfile.sh # if you changed deps; otherwise skip
git push

# 2. tag and sign
git tag -s v0.1.1 -m "giz v0.1.1"
git push origin v0.1.1

# 3. compute the SHA-256 of the source tarball GitHub will serve
curl -fsSL https://github.com/ulascim/giz/archive/refs/tags/v0.1.1.tar.gz \
    | shasum -a 256
# -> abcdef0123... (note this value)

# 4. attach briar-headless JARs to the GitHub Release
gh release create v0.1.1 \
    briar-headless-macos-aarch64.jar \
    briar-headless-windows-x86_64.jar \
    --title "giz v0.1.1" \
    --notes "$(git log v0.1.0..v0.1.1 --pretty=format:'- %s')"

# 5. compute SHA-256 of each uploaded JAR
shasum -a 256 briar-headless-macos-aarch64.jar
shasum -a 256 briar-headless-windows-x86_64.jar

# 6. update install.sh and install.ps1:
#      GIZ_VERSION   -> v0.1.1
#      SOURCE_SHA    -> the value from step 3
#      JAR_SHA_MACOS_AARCH64    -> the value from step 5 (mac line)
#      JAR_SHA_WINDOWS_X86_64   -> the value from step 5 (win line)
#    The installers DO NOT live inside the tag; they live on main and
#    are downloaded from raw.githubusercontent.com at install time.
#    Updating them after the tag is the intended workflow.

# 7. commit + push the installer SHA bumps to main
git add install.sh install.ps1
git commit -m "install: pin source + JAR SHAs for v0.1.1"
git push
```

## Verification before announcing

From a clean machine:

```bash
# tag signature must validate
git clone https://github.com/ulascim/giz && cd giz
git verify-tag v0.1.1

# tarball SHA must match install.sh
curl -fsSL https://github.com/ulascim/giz/archive/refs/tags/v0.1.1.tar.gz \
    | shasum -a 256
grep -E '^SOURCE_SHA' install.sh

# the install must succeed end-to-end
curl -fsSL https://raw.githubusercontent.com/ulascim/giz/main/install.sh | bash
```

If any of these fails: do not announce. Roll back the tag (`git push
--delete origin v0.1.1` and `git tag -d v0.1.1`), fix, retag with the
same number.

## Updating dependencies

When changing `requirements.txt` (pinned version) you MUST regenerate
`requirements.lock.txt` so the hashes are consistent:

```bash
python3 -m venv /tmp/lockenv
/tmp/lockenv/bin/pip install --quiet --upgrade pip pip-tools
/tmp/lockenv/bin/pip-compile --generate-hashes --strip-extras \
    --output-file requirements.lock.txt requirements.txt
rm -rf /tmp/lockenv
```

The lockfile is what the installer uses (`pip install
--require-hashes -r requirements.lock.txt`); `requirements.txt` is a
human-readable summary only.

Always sanity-check the lockfile actually installs cleanly:

```bash
TMPVENV=$(mktemp -d)/v
python3 -m venv "$TMPVENV"
"$TMPVENV/bin/pip" install --quiet --upgrade pip
"$TMPVENV/bin/pip" install --require-hashes -r requirements.lock.txt
rm -rf "$(dirname "$TMPVENV")"
```

If the lockfile fails this test, do not push. Fix it first.

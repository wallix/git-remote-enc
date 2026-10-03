# git-remote-enc — design

`git-remote-enc` is a git remote helper that stores an end-to-end encrypted
repository inside an ordinary git repository on an untrusted host. The host
(GitLab, GitHub, a bare repo over ssh, anything `git push` reaches) sees one
branch of opaque blobs. Only the participants named in a signed manifest can
read the refs, the history or even the participant list.

This document is the authoritative description of the on-remote format and the
protocol. The format is a compatibility contract: any change to it bumps the
manifest version (section 4.1).

## 1. Goals and non-goals

Goals

- **Confidentiality and integrity** of the repository against the host and
  anyone with read access to the hosting repository: refs, objects, ref names,
  commit metadata and the participant list are never visible in clear. What
  does show is listed in section 6.4, the backend branch name first.
- **Access control decided by the owner:** a participant list of public keys,
  carried in the manifest and signed. Adding a reader is a manifest rewrite;
  no out-of-band shared config.
- **Plain git semantics:** `git clone`, `fetch`, `push`, `pull` behave as with
  any remote. A non-fast-forward push is rejected; concurrent pushers never
  overwrite each other.
- **Incremental transfer:** a push or fetch costs proportional to the new
  objects, not to the history. No periodic full re-upload.
- **Works with a hosting service** over the transports it already offers (ssh,
  https). No rsync, no special server side, no shell access to the host.
- **Modern, boring crypto** with reference implementations: age (X25519 +
  ChaCha20-Poly1305) and SSH signatures. Participants reuse the SSH key they
  already use with the host.

Non-goals

- Hiding traffic analysis: the host sees push/fetch times, the number and size
  of encrypted packs, and the pushing account.
- Revoking read access to *past* history from a removed participant. They had
  the bytes; rotation only protects future pushes (section 6.3).
- Fine-grained per-branch permissions inside one remote. Any participant with a
  signing key may update any ref. Use separate remotes for separate audiences.
- Compatibility with the git-remote-gcrypt format.

## 2. Why not git-remote-gcrypt

git-remote-gcrypt's design is sound (encrypted packs named by hash, an
encrypted+signed manifest listing refs and pack keys) but two properties of its
implementation make it impractical on a git host. Both were measured on
gcrypt 1.5 against a local bare repository (4 pushes of 300 KB each):

| | gcrypt | after chaining backend commits |
|---|---|---|
| bytes received by the host on push 4 | 1.20 MB | 0.30 MB |
| bytes fetched after one new push | 1.72 MB | 0.30 MB |

- **Whole-history re-upload on every push and fetch.** Each gcrypt push writes
  a *parentless* root commit to the backend branch and deletes its local
  tracking ref afterwards. Git's transfer negotiation only marks the trees of
  *parent* commits as already-present, so every encrypted pack blob is sent
  again each time, in both directions. Chaining the commits (`-p` on the
  previous tip) and keeping the tracking ref makes both directions incremental.
- **Every push is a force push.** gcrypt never checks fast-forward itself, and
  git only checks it for a helper when the old tip object happens to be local
  (a missing object is passed through instead of being rejected as
  `fetch first`). The manifest is then rewritten blindly, and the backend
  branch is pushed with `-f`, so two concurrent pushers silently lose one
  another's packs. A git backend can do a real compare-and-swap with
  `--force-with-lease`; rsync/sftp cannot, which is why gcrypt's "good" backend
  cannot fix this.
- Secondary: full repack of the whole history every 25 pushes (unnecessary on a
  git backend, where N small blobs cost one round trip), packs are not thin
  (a modified file is re-uploaded whole), GnuPG as the only crypto engine.

## 3. Architecture

```
  git  ──stdin/stdout──▶  git-remote-enc  ──git plumbing──▶  local repo ($GIT_DIR)
        (helper protocol)        │                              │
                                 │ age / ssh-key                │ git fetch / push
                                 ▼                              ▼
                        manifest, pack keys,           backend branch on the host
                        signatures (in memory)          (tree of opaque blobs)
```

Two crates:

- `enccore` — the library: `git` (plumbing wrappers), `manifest`, `crypto`,
  `backend` (git-hosted store), `state` (local per-remote state), `remote`
  (connect / list / fetch / push), `config`, `guard` (pre-push hook,
  section 6.7).
- `git-remote-enc` — the protocol loop, inspection subcommands (`manifest`,
  `participants`, `log`) and setup ones (`init`, `invite`, `join`,
  `doctor`, `install-hook`; section 8.1), over `enccore`'s `setup`.

All object-level work (pack generation, thin-pack completion, indexing, transfer
negotiation) is delegated to `git pack-objects`, `git index-pack`, `git fetch`
and `git push`. The helper never parses a pack beyond its 12-byte header. This
keeps the code small and guarantees that transfers follow git's own reachability
semantics.

## 4. On-remote format

### 4.1 Backend tree

The remote is one branch of a git repository (default `refs/heads/enc`,
overridable with a URL fragment: `enc::git@gitlab.com:g/r.git#mybranch`). Each
push appends exactly one commit, whose first parent is the previous tip (a
large push's staging commits join as a further parent, section 5.1), with a
fixed anonymous author/committer/date and the message `enc` (`enc epoch <n>`
for a rewrite's first commit, section 6.2). Its tree is flat:

```
manifest              age file: the encrypted, signed manifest
<sha256-hex>.age      age file: one encrypted git pack, per push
<sha256-hex>.age.0000 a pack over the part size, as consecutive parts
<sha256-hex>.age.0001 (at least four digits: .9999 is followed by .10000)
...
```

Blob names are the SHA-256 of the age ciphertext, so the manifest can bind a
pack line to exactly one ciphertext, stored whole or as parts (section 4.4).
The tree only ever grows (a deleted ref keeps its objects in earlier packs);
section 7 discusses repacking.

Chained commits make both fetches and pushes of the branch incremental. No
object is ever transferred twice in either direction.

### 4.2 Manifest

The manifest plaintext is UTF-8 text, one item per line, `\n`-terminated. Its
first line is the format tag. Version 4:

```
enc-manifest 4
generation 42
time 1790000000
previous 9a4c...e1
repo 3f9c6e4d0b1a2c7e8d9f0a1b2c3d4e5f
head refs/heads/main
participant ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop
participant ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... bob@ci
participant age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
admin ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop
ref 7f3a...c1 refs/heads/main
ref 91b2...4e refs/tags/v1.0
pack 5b0e...d7 AGE-SECRET-KEY-1QG5...
pack a3c1...20 AGE-SECRET-KEY-1K7W...
```

| item | meaning |
|---|---|
| `enc-manifest <n>` | format version; a reader refuses an unknown `n`. Readers accept 1 to 4 and write 4 |
| `generation <n>` | strictly increasing per push; anti-rollback (section 6.2) |
| `time <unix seconds>` | when the pusher wrote it, by the pusher's clock; for the audit trail only, never for trust decisions. New in version 2 |
| `previous <sha256>` | hex SHA-256 of the previous generation's manifest text; absent on a remote's first manifest. Chains the history so the accepted manifest authenticates every one before it (section 6.6). New in version 3 |
| `snapshot <pack> <history pack or -> <commit>…` | the pack of the last repack that holds the ref tips of then, each with its whole tree and no parents; the pack holding the rest of the history; and the snapshot's commits (section 7). Every pack but the history pack usually makes a shallow clone with those commits as its boundary; a pack or ref that needs objects or commits older than the snapshot needs the history pack too. Carried forward by every push. New in version 4 |
| `epoch <generation>` | the generation the backend history starts at since a participant rewrote it (section 7); at most `generation`, carried forward by every push. New in version 4 |
| `repo <hex>` | random id chosen at creation; detects a recreated remote |
| `head <ref>` | what `HEAD` points to on clone (first pushed branch by default) |
| `participant <key>` | an `ssh-ed25519` public key (may read, may push) or an `age1…` recipient (read-only, cannot sign) |
| `admin <key>` | a participant (`ssh-ed25519`) who may change the `participant` and `admin` lists (section 6.1). New in version 2; a version 1 manifest has none |
| `ref <oid> <name>` | a git ref and its object id, as in `git ls-remote` |
| `pack <sha256> <age-secret-key>` | a pack blob and the X25519 identity that decrypts it, in append order |
| `extn <name> …` | reserved: unknown items are preserved verbatim by writers that do not understand them |

Pack lines are ordered: a pack may be *thin* relative to every pack before it,
so a reader indexes them in manifest order (section 5.2).

A reader refuses a manifest that repeats `generation`, `time`, `previous`,
`epoch`, `snapshot`, `repo` or `head`, lists one ref name or one pack twice,
names a ref (in `ref` or `head`) that `git check-ref-format` would refuse or
that does not start with `refs/`, or has a `snapshot` naming a pack it does
not list.

A reader holds the manifest in memory to decrypt and verify it, before it
can tell who wrote it, so it refuses a manifest blob over 64 MiB (about
450,000 pushes' worth of pack lines) without reading it.

Versions 1 and 2 come from pre-release builds: version 1 had no `admin`
item, version 2 no `previous` item. Version 3 (v0.1.0) has the same grammar
as version 4, but its packs are always stored whole: version 4 tells an
older reader that a pack may be stored as parts (section 4.4), which it
could not read. Readers accept all four, and the first push rewrites any as
version 4 (a version 1 manifest with an empty admin list).

### 4.3 Manifest envelope

```
plaintext  = manifest text
sig        = SSH signature over plaintext, namespace "git-remote-enc",
             hash sha512, PEM ("-----BEGIN SSH SIGNATURE-----")
envelope   = plaintext ‖ sig
blob       = age.Encrypt(recipients = all participants, envelope)
```

Sign-then-encrypt: the signer's identity is inside the ciphertext, so the host
cannot tell which participant pushed. The recipient stanzas in the age header
do reveal the *number* of participants and, for `ssh-*` recipients, a short
tag derived from the public key (this is inherent to age's ssh recipient
types). Public keys are routinely published, so that tag can name the
participants; section 6.4 has the consequence and the mitigation. An
`age1…` recipient stanza carries no key tag.

### 4.4 Pack blobs

Each push produces at most one pack:

```
pack       = git pack-objects --thin --stdout  (section 5.1)
key        = fresh X25519 identity
blob       = age.Encrypt(recipients = [key.public], pack)
name       = hex(sha256(blob)) ‖ ".age"
```

A blob larger than the part size (`enc.partSize`, default 1 GiB) is stored
as parts of that size, `<name>.0000`, `<name>.0001`, … (a decimal index of
at least four digits), whose concatenation is the ciphertext; the manifest is
the same either way. Parts bound what one object and one push (5.1) cost the
host. The default stays above git's `core.bigFileThreshold` (512 MiB): git
searches smaller blobs for deltas whenever it packs them (a host's repack, or
serving loose objects to a fetch), measured at about 3 minutes of CPU per GiB
of ciphertext, for no gain. A forge with a per-file limit below that (GitHub
refuses files over 100 MB) needs a smaller part size and pays that cost. A
reader takes `<name>` if present, else the parts from `.0000` up to the first
gap; the SHA-256 check of section 5.2 covers the concatenation, so a
missing or reordered part, or an extra one right after the last, fails the
fetch (parts past a gap are never read). Parts are new in manifest version 4.

The helper stores backend blobs uncompressed and pushes them without
compression or delta search (`core.looseCompression=0`, `pack.compression=0`,
`pack.window=0` in the backend repository's config, section 5.4): ciphertext
gains nothing from either. The host's own storage and fetch responses follow
its configuration.

The per-pack identity goes in the manifest's `pack` line. Encrypting to a
throwaway X25519 key rather than using a raw symmetric key keeps every
ciphertext a standard age file (`age -d -i <key>` reads it), with age's own
chunked AEAD (64 KiB ChaCha20-Poly1305 STREAM), for the cost of one X25519
operation per pack.

## 5. Protocol

### 5.1 Push

Invoked by git as a batch of `push [+]<src>:<dst>` lines after `list
for-push`.

1. **Connect** (once per helper process): in the backend repository (5.4),
   `git fetch origin +<branch>:refs/enc/tip`, which brings commits, trees and
   blobs up to 1 MiB (the manifests, and pack blobs that small) and leaves
   larger blobs on the host; a manifest over 1 MiB is then fetched by id. A
   missing branch means a new remote. Read `manifest` from the tip's tree,
   decrypt with the local identities, split the envelope, verify the
   signature (section 6), parse.
2. **Ref checks**, for each refspec, in the helper (git does not do it reliably
   for helpers, section 2):
   - deletion (`:<dst>`): allowed;
   - `<dst>` unknown on the remote: create;
   - `<dst>` known, `+` or `--force`: update;
   - otherwise the old tip must exist locally (`error <dst> fetch first`) and
     be an ancestor of the new one (`error <dst> non-fast-forward`).
   Refs that fail are reported and skipped; the others proceed, as git does.
3. **Pack.** `git pack-objects --revs --thin --stdout` with stdin
   `<new oid>…` then `^<oid>` for every manifest ref whose object exists
   locally. Everything reachable from a manifest ref is on the remote, so the
   pack contains only new objects and may use deltas against remote objects
   (thin). An empty pack (object count 0 in the header) is not stored.
4. **Encrypt + hash** the pack stream into temporary files under
   `<common>/enc/`, cut at the part size, then `git hash-object -w` each.
   When the parts exceed one upload batch (`enc.uploadBatch`, default
   1 GiB), they are pushed ahead of the manifest, a batch per push, as a
   chain of commits on a staging branch `<branch>-upload-<random>`, so a
   per-push size limit applies to one batch, not the whole pack. The commit
   of step 6 takes the staging chain's tip as a further parent (its only one
   on a new remote), so git knows the host has the parts and sends only the
   manifest; `log` follows first parents and skips staging commits. A lost
   race (step 7) keeps the staging chain, so the retry sends only its new
   manifest commit. The staging branch is deleted once the push succeeds or
   fails, and a failed push uploads the whole pack again next time; a helper
   killed in between leaves the branch behind, and it can be deleted by
   hand.
5. **New manifest:** refs updated, pack line appended, `generation + 1`,
   participants unchanged (from config only when creating the remote, or for
   `git-remote-enc participants --apply`, section 6.3), `head` set if absent.
   Sign with the local signing key, encrypt to the participants.
6. **Commit:** tree = previous tree + pack blobs + new `manifest`;
   `commit-tree -p <old tip>`, plus `-p <staging tip>` after step 4 staged.
7. **Compare-and-swap:** `git push <url> <commit>:<branch>
   --force-with-lease=<branch>:<old tip>` (empty old tip for a new remote:
   "must not exist"). On a stale lease someone pushed in between: go back to
   step 1 and redo everything (at most 3 attempts) except the pack, which is
   kept when the same tips are pushed again and every pack listed when it was
   built still is: everything it was built against is then still on the
   remote. It is dropped, and step 3 runs again, when the new manifest
   already lists it (our push landed although git reported a failure; it is
   recorded as indexed), already holds every pushed tip, or a repack has
   dropped a pack it was built against. Their pack is still valid too. A
   repack's packs (section 7) are not thin: they are kept whenever the refs
   are unchanged, and a repack whose packs are exactly those the new
   manifest lists has landed and is done. The lease is checked by the client
   (`stale info`) and enforced again by the server (old value mismatch); any
   rejection after which the branch tip has moved is treated as a lost race,
   anything else as a hard error.
8. Move the tracking ref to the new commit, record the new packs as indexed
   locally (its objects are ours), report `ok <dst>` per ref.

The lease makes concurrent pushes safe: the manifest we replace is provably the
one we read, so no pack line can be lost.

**Git LFS.** LFS replaces tracked files by pointers and uploads their
content from its pre-push hook to a separate LFS server, usually the forge
named by the product's `.lfsconfig`. The helper sees only the pointers; the
files would leave in clear, with the push succeeding. git calls the helper's
`list for-push` before it runs the pre-push hook, so the helper refuses there
when LFS could upload anything, unless `enc-allowLfs` is set. LFS uploads
only from its local storage (`<common dir>/lfs/objects`, or under
`lfs.storage`), so the test is: that storage holds a file, and a pre-push
hook other than the guard exists (`hooks/pre-push`, under `core.hooksPath`
too, or a `hook.*.command`). A hook is a shell script whose effect cannot be
read off its text, so any such hook counts. Setting it is for a clone where
LFS was neutralized (`lfs.url` pointed at nothing in the local config, which
overrides `.lfsconfig`). Without LFS's hook, the push carries the pointers
and not the files, and the other participants get nothing to resolve them
with; so a push whose new blobs include an LFS pointer (a blob of at most
1024 bytes in the pointer format) is refused as well, unless
`enc-allowLfs` is set. Encrypting LFS objects into the backend, as a custom
LFS transfer agent, is not implemented.

**Shallow clones.** A shallow clone lacks the parents of its boundary
commits (`$GIT_DIR/shallow`), and `pack-objects` stops at them: a pack of a
range that reaches a boundary names parents it does not carry, and every
fetch of it fails git's connectivity check. A push is refused when a commit
reachable from the new tips but not from the manifest refs is a boundary,
with a hint to `git fetch --unshallow`. A boundary the remote already holds is
fine, so a shallow clone of a populated remote still pushes new commits. So is
a boundary this remote set (section 5.2): a snapshot commit, whose parents
the remote holds. The helper records the boundary it sets and fetches the
history behind it when a fetch needs it; a boundary set by another remote it
leaves alone, as the shallow file does not record where a boundary came from.

### 5.2 Fetch

After `list`, git sends the `fetch <oid> <name>` lines it wants. The helper
ignores the individual wants and downloads every pack it has not indexed yet:

1. Fetch the blobs of every `pack` line not in the local `have` list into
   the backend repository, in one `git fetch --stdin origin` given their
   ids. Then for each, in manifest order: `git cat-file blob` of the blob or
   each part in turn → age decrypt with the pack key → `git index-pack
   --stdin --fix-thin --fsck-objects` in the user's repository → append to
   `have`.
2. The SHA-256 of the ciphertext is checked against the pack name first, in
   a separate read of the blob, so nothing from a mismatching blob reaches
   the object store; a mismatch fails the fetch.

Order matters because `--fix-thin` completes a thin pack with base objects
that must already be present.

**Shallow clones.** git passes `--depth` as `option depth <n>`, `--deepen`
as `option depth <n>` followed by `option deepen-relative true`, and
`--unshallow` as `option depth 2147483647`. The helper answers
`--shallow-since` and `--shallow-exclude` (`option deepen-since`, `option
deepen-not`) with an error, and fails the fetch that follows, as `git clone`
goes on after an option's error. Packs are the unit, so a depth is honoured
at their granularity: with a depth, or in a repository this remote already
made shallow, a fetch skips the history pack of the manifest's `snapshot` and
indexes every other pack: the snapshot, then the packs pushed since. The
snapshot's commits whose parents are missing and that a manifest ref reaches
(a branch deleted since the repack leaves its tip unreached) are added to
`$GIT_DIR/shallow`, under git's `shallow.lock`, and recorded in
`<common>/enc/<key>/shallow`, before the shallow file changes, so that
deepening removes those and no other remote's. A recorded commit stays a
boundary while it is present and its parents are not, across later repacks
and fetches (`--unshallow` included) whose history pack does not hold them:
a repack after an orphan was pushed has none, and a later history pack need
not reach an older snapshot. One pruned since (by `git gc`) is dropped. The clone has at least the depth
asked for: everything since the last repack. A pack that does not index
without the history (`index-pack` reports unresolved deltas: their bases are
there), or refs that do not reach the boundary through what was indexed (a
push onto a commit older than the snapshot, as git's connectivity check
`rev-list --objects --stdin --not --all` tells), fetch the history pack after
all. So does, without a depth asked for, a snapshot commit that would be a
new boundary (a repack since the last fetch, whose snapshot builds on
commits not fetched before): the clone stays connected rather than cut
anew. The cost: a plain fetch into a `--depth` clone that a repack has
overtaken downloads the whole history pack and unshallows it, even when the
clone has no local work to keep connected; a fetch with `--depth` cuts it
anew instead. An explicit `--depth` may cut anew, and does not deepen a clone
already shallow, which a note says. `--unshallow` and `--deepen`
fetch it and remove the boundary; there is no depth between the two. With
every pack indexed, a recorded commit that stays a boundary lacks parents
the remote no longer holds: the fetch names it, and how to drop it (delete
the local refs that reach it, expire the reflogs, `git gc --prune=now`). A
remote with no snapshot (never repacked) is fetched whole, with a note.
`$GIT_DIR/shallow` keeps its mode when rewritten; a new one gets
`core.sharedRepository`'s.
`repack` indexes the history pack first: it repacks everything. A push from
a shallow clone may reach the boundary only at the current snapshot's
commits, when it has a history pack: the remote holds their parents. Any
other boundary commit (another remote's, or an older snapshot's whose
history a later repack dropped) refuses the push.

**Progress.** The helper advertises the `option` capability and follows
git's `option progress`: on for a terminal unless `-q`, or with `--progress`.
It then shows git's own progress for the backend fetch and push, for
`pack-objects` and for `index-pack`, and its own meters for storing and
verifying pack blobs.

Configured identities are loaded, and a key passphrase asked for, before the
backend fetch.

The packs reach the object store through `index-pack` run by the helper, not
through `git fetch`, which would otherwise check them. The helper therefore
checks every object as `fetch.fsckObjects` would (a tree entry named `.git`,
malformed objects), and does so by default, unlike git: content from a remote
everyone trusts is where a hostile object does the most harm.
`fetch.fsck.<msg-id>` severities and `fetch.fsck.skipList` apply;
`fetch.fsckObjects = false` (or `transfer.fsckObjects = false`) turns it off.

### 5.3 List

`list` and `list for-push` print `<oid> <ref>` for each manifest ref and
`@<head> HEAD`.

### 5.4 Local state

Per remote, keyed by `sha256(url ‖ branch)[..16]`, under the repository's
common directory (`git rev-parse --git-common-dir`: the main `.git`, shared by
every linked worktree, so trust accepted in one worktree holds in all):

- `<common>/enc/<key>/backend.git` — the backend repository: a bare partial
  clone of the backend branch (`remote.origin.partialclonefilter
  blob:limit=1m`), owned by the helper, tracking it as `refs/enc/tip`. Every
  command in it runs with `GIT_NO_LAZY_FETCH=1`, so a stray read of a missing
  pack blob fails instead of downloading it, and blobs are fetched
  explicitly by id. It does not read the user repository's config; the
  transport settings there (`url.*.insteadOf`, `core.sshCommand`, `http.*`,
  `credential.*`, `ssh.*`, `protocol.*`) are passed on as `GIT_CONFIG_*`
  variables, which, unlike `-c` arguments, other local users cannot read.
  Global and system config apply as usual, but their conditional includes
  are evaluated for `backend.git`: `gitdir:<dir>/` still matches (the
  repository is inside the user's `.git`), `gitdir:` naming the user's git
  directory exactly does not, and `hasconfig:remote.*.url:` sees the host
  URL. `GIT_NO_LAZY_FETCH` needs git 2.45 or later; older versions ignore
  it and download such a blob silently. The repository is created on
  contact, in `tmp/` then renamed into place, with the user repository's
  object format. A host that does not support filters
  (`uploadpack.allowFilter` unset on a plain bare repository) sends
  everything, as before. Pack blobs are then fetched by id, which needs
  protocol v2 or `uploadpack.allowAnySHA1InWant` on the host: a host that
  filters but serves protocol v0 only (ssh to an sshd without `AcceptEnv
  GIT_PROTOCOL`) fails every pack fetch. Versions before it kept the branch as
  `refs/enc/<key>` in the user's repository: on the next contact that ref
  stands in for the backend repository's once (trust and rewrite checks),
  then is deleted, and its objects go when the repository's gc prunes them
  (`gc.pruneExpire`).
- `<common>/enc/<key>.known` — an empty file: a manifest from this remote was
  accepted. It is outside `<key>/` so that losing that directory, trust state
  and backend repository together, is not taken for a first contact.
- `<common>/enc/<key>/have` — pack names already indexed.
- `<common>/enc/<key>/shallow` — the boundary commits this remote added to
  `$GIT_DIR/shallow` (section 5.2), which deepening removes. It survives
  `forget`, `git remote remove` and a URL change, as those commits' parents
  are still missing: to the remote under a new key (another URL or branch) or
  any other remote, they are a boundary it cannot complete, which `doctor`
  reports and a push reaching them is refused at. `git fetch --unshallow`
  from the old URL and branch removes them; otherwise, once their parents
  are present, delete them from `$GIT_DIR/shallow` and the list by hand.
  One whose parents the remote no longer holds goes once no ref reaches it
  and a `git gc` prunes it; `doctor` says so instead of `--unshallow`.
- `<common>/enc/<key>/trust` — the last accepted manifest's `generation`,
  `repo` id, participant list, the SHA-256 of its text and the backend commit
  that carried it (section 6), ending
  in `mac <key id> <tag>`: HMAC-SHA256 of the lines above, keyed by
  HMAC-SHA256(identity secret, "git-remote-enc local trust state v1") for the
  first configured identity (`key id` is its public fingerprint or age
  recipient). A file whose tag does not verify, or that has no tag line, is
  refused; so is state written by pre-release builds, which had none. The tag stops a
  rewrite by anything that lacks the private key; it does not stop someone who
  can write `.git` and simply runs code through a hook instead.
- `<common>/enc/<key>/tmp/` — temporary files for the pack pipeline.

`<common>/enc/` and each `<key>/` directory are made mode 0700 on every run.
The decrypted objects are ordinary objects of the repository, as readable as
the umask left `.git`, and `forget` does not remove them: they are the
repository. Once an embargo ends, the clone is deleted (on an encrypted disk,
that is the whole cleanup), and the backend branch and any mirror of it are
deleted on the host once the audit trail (`log`) has been exported.

Pack blobs do not stay in the backend repository once used. A push's part
blobs, written loose (or, over `core.bigFileThreshold`, in a pack of their
own), are deleted once the host has them, or once the attempt is abandoned;
a push that lost a race keeps them for its retry. Before deletion, and after
every successful push, the commits, trees and manifests reachable from the
tracking ref that no promisor pack holds or names (a push of ours) move into
a pack with a `.promisor` file: git then treats the pack blobs they name as
promisor objects, which may be missing, and `repack`, `gc` and `fsck` do not
fail on a dropped one. A fetch from a promisor remote always keeps the pack
it receives, so pack blobs fetched by id land in packs of their own; once
the fetch's packs are indexed, the promisor packs that hold only pack blobs
of the backend tree are deleted, as are loose copies of them, except packs
with a `.keep` (a fetch in flight). A manifest over the filter is fetched by
id into its own promisor pack. Cleanup keeps this pack because the manifest
is not a pack blob, so it is fetched only once. Only reindexing a pack
(`ensure_blobs`) fetches a deleted pack blob again: backend commands run
with `GIT_NO_LAZY_FETCH`. No pack is deleted while a `multi-pack-index`
exists, which would name it. Backend fetches run with `--no-auto-gc` and the
repository has `gc.autoPackLimit=0` to keep blob packs separate until
deletion. The helper then runs `gc --auto` in the foreground
(`gc.autoDetach=false`), so it cannot race the next helper run, and reports
a failure. Pack blobs under the 1 MiB filter that arrived with the branch
remain, as do all pack blobs fetched from a host without filter support.

## 6. Trust model

### 6.1 Who may write

A manifest is accepted only if it is signed by a participant of the **previously
accepted** manifest. On first contact there is no previous manifest:

- if another remote of the same local repository has already accepted a
  manifest with this `repo` id (the same remote reached through a different
  URL spelling), that state applies, signer check and rollback check included;
- else if the local config names participants (`enc-participants`), the signer
  must be one of them;
- else the manifest is refused, and the error names the signer's fingerprint
  to confirm out of band. `enc.trustOnFirstUse = true` accepts it unverified
  (trust on first use) instead.

Without a pinned list, whoever controls the host on first contact chooses what
the new clone trusts: they cannot read an existing remote, but they can serve
a fabricated one, and anything pushed to it lands in a history they control.

A pinned list is not enough on its own: the host can still serve any manifest
a pinned key ever signed, an old generation of this remote (from before a
participant was removed, so the new clone re-encrypts to them) or another
remote with the same signer. `enc-repo` pins the `repo` id and
`enc-minGeneration` a floor for `generation`, both learned out of band with
the key; a manifest that does not match is refused, on first contact and
after. The first-contact message prints both values, and says when they were
not pinned.

After acceptance the participant list is stored locally, so:

- an admin of the accepted manifest may add or remove participants (including
  themselves) or admins, but may not remove every admin; only while the
  accepted manifest has no admins may any trusted signer change these lists;
- an attacker with write access to the hosting repository cannot inject a
  manifest: they can encrypt to us, but they cannot produce a signature by a
  trusted key;
- consequently a compromised host can at most **withhold** or **roll back**
  (6.2), never forge.

Any participant that can sign may push refs; only an **admin** may change who
participates. A manifest is accepted over the previous one only if either it
leaves the `participant` and `admin` lists unchanged (compared by key), or its
signer is an admin of the previous manifest; and once a remote has admins, a
manifest with none is refused. Every admin must be an `ssh-ed25519`
participant. A new remote's admins are `enc-admins` if configured, else its
creator. Writers enforce the same rules before pushing, so a refused change
never reaches the host.

A remote created before version 2 has no admins, and then any signing
participant may change the lists, as in version 1, with a warning;
`git-remote-enc participants --apply` with `enc-admins` set appoints them.
Read-only participants (`age1…` keys) cannot sign and therefore cannot push.

### 6.2 Rollback

`generation` is strictly increasing. A reader refuses a manifest whose
generation is lower than the last one it accepted, and one whose generation
is equal but whose content differs (compared by the SHA-256 of the manifest
text kept in the local state): two validly signed manifests with one
generation mean the history forked, because the host served different views
or rewound the branch under a pusher. Which view to keep is the
participants' decision; `enc.refuseForks = false` accepts the one served,
with a warning, and it becomes the baseline. A pusher always writes
`previous + 1`; the lease guarantees "previous" is the real tip.

Generations are bounded from above too. Each push adds one commit to the backend
branch's first-parent chain and one generation, so a manifest may be at most the
accepted generation plus the number of first-parent commits since the accepted
one's (recorded in the local state), or on first contact, the number of
first-parent commits on the branch, plus `epoch - 1` when the branch starts at
the manifest's `epoch` (a participant rewrote it, section 7). It does when its
oldest commit carrying a manifest (staging commits skipped) has the message
`enc epoch <epoch>`, and every commit carrying a manifest is on the
first-parent chain; otherwise `epoch` is ignored. The message is not signed,
but placing it under the history takes a forced update, or creating the branch
(a new remote, or after deleting it): an ordinary push can only add commits on
top, and a fast-forward that hides the history behind a second parent fails the
second condition. A new remote's first push, or a rewrite, may start on a
staging chain (section 5.1), whose commits then count too: the bound is that much looser, never tighter. Without the bound, a
participant could sign `generation 18446744073709551615`: every reader would
accept it, no push could follow it, and restoring the branch would read as a
rollback. A manifest over the bound is refused, never accepted, so the host
restoring the branch recovers. A participant whom the host lets force-update
the branch can still lift the first-contact bound, by a rewrite with a large
`epoch`, and so can the remote's creator, whose first push may be a single
`enc epoch 18446744073709551615` commit; nothing local tells either from a real
rewrite. A client whose accepted manifest's commit is no longer in the history
bounds the generation the same way when the manifest's `epoch` is above the
generation it accepted and the history starts there, so it accepts the same;
otherwise (older local state, or the host's rewrite, which it reports) it is
unbounded. The host can forge the message too, but not a signed `epoch` to
match it.

### 6.3 Adding and removing participants

The participant and admin lists change only on request, by an admin
(section 6.1): `git-remote-enc participants <remote>` shows the remote's lists
and how the configured ones (`enc-participants`, `enc-admins`) differ, and
`--apply` pushes a manifest carrying the configured lists and no ref change.
An ordinary push keeps the remote's lists, so a clone with a stale or partial
configuration cannot drop someone as a side effect of an unrelated push.

Adding a reader is cheap: re-encrypt the manifest to the new set (the pack keys
are inside it, so all history becomes readable). Removing a participant
re-encrypts the manifest without them; every *future* pack key is then unknown
to them. Past pack keys were in manifests they could read, so past history
stays readable to them — this is inherent, and identical to gcrypt. Full
revocation means a fresh remote and a re-push (`git push --mirror`).

### 6.4 What the host learns

- **The backend branch name**, in clear: it is a ref on the host, and anyone
  who can read the hosting repository (`git ls-remote`) sees it, with the
  times its commits appeared. The name comes from the URL fragment (`#<name>`,
  default `enc`); a descriptive one (`embargo-CVE-2026-31337`) tells every
  reader of the host what is being worked on and since when. Use a neutral
  name, or one opaque remote per audience with the default name.
- Number and size of packs, timing, pushing account (transport layer).
- After `repack --rewrite-history`, the generation it was made at (its
  commit's message, section 6.2): the number of pushes before it, which the
  host saw happen.
- Number of participants (age recipient stanzas), and for `ssh-*` recipients a
  4-byte tag derived from the public key. That tag identifies the key to
  anyone who holds the public key, and public keys are not secret: forges
  publish every user's SSH keys without authentication
  (`https://<forge>/<user>.keys`). Whoever collects the published keys of an
  organisation can therefore tell which of those keys each manifest is
  encrypted to, i.e. who participates. Where membership itself is sensitive,
  use participant keys that are not published anywhere (a dedicated
  `ssh-ed25519` key per remote, not the key registered with the forge) or
  `age1…` recipients, whose stanzas carry no key tag.
- Nothing about refs, object ids, commit metadata, file names, or who signed.

### 6.5 Key material on the client

Identities are OpenSSH private keys (`ssh-ed25519`; passphrase
protected keys are decrypted with a prompt on `/dev/tty`) or age identity
files. ssh-agent cannot be used for decryption: X25519 key agreement is not an
agent operation. The same SSH key signs; signing therefore also uses the key
file, not the agent. Hardware-backed keys (age plugins, FIDO) are not
supported in v1. As with ssh, an identity file that its group or others can
access is refused.

In memory, the decrypted manifest, every pack key, the key passphrase, the key
derived for the local trust state, the identity file as read and the decrypted
key re-encoded for age are wiped when dropped (`zeroize`); the private keys
themselves are wiped by age and ssh-key. age's parser keeps a copy of the key
text while parsing, which it does not wipe. Pack keys are left out of debug
output. Pages are not locked (`mlock`), so a secret can still reach swap or a
core dump while it is live: run with encrypted swap and core dumps disabled
where that matters.

### 6.6 Audit trail

The backend commits are anonymous and undated by design (section 4.1), so the
audit trail lives inside the encrypted history instead: every manifest names
its signer through its signature and carries its `time`, and the backend
branch keeps every past manifest. `git-remote-enc log <remote>` walks the
branch and prints, per generation, the signer, the time, and the ref,
participant and admin changes. Manifests from before one's own key was added
are not readable and are listed as such. `time` is self-asserted by the pusher:
nothing on the host or in the format can vouch for it, and `log` only flags a
time earlier than the generation before. The host's own push log, where it
keeps one, is the independent clock.

The host controls that branch and can rewrite it, e.g. squash past commits
into one, without touching the current manifest. Two checks surface it:
connect warns when the new tip does not descend from the tip fetched before
(the forced fetch leaves the old one in the object store), and `log` reports
every place where the generations stop following the commits one for one
(each push adds one commit and one generation), printing which generation a
manifest's changes are relative to when that is not the one just before. Both
detect a rewrite; neither restores what it removed. A participant's rewrite
(`repack --rewrite-history`, section 7) is signed via `epoch` and reported as
a participant's, not the host's. A host squashing the history after such a
rewrite is still reported as a participant's repack, but `log` flags the
discontinuity.

A signature alone does not make a past manifest authentic: the host can
insert manifests signed by a key of its own, encrypted to a participant, whose
own participant list names that key after someone else. Every manifest
therefore carries the SHA-256 of its predecessor's text (`previous`). `log`
starts from the manifest connect accepted, which is authentic, and follows the
chain down; a manifest reached that way is verified, and every one below the
first break (a digest that does not match, an unreadable manifest, a manifest
from before version 3 had `previous`) is printed as not verified, with its
signer as a bare fingerprint, and the changes relative to it flagged. Connect
also refuses a manifest one generation past the accepted one whose
`previous` is not the accepted one's digest: the history forked (6.2). Protecting the branch on
the host against force pushes, and keeping the host's push log, does.

### 6.7 Publishing by mistake

Encryption ends at `$GIT_DIR`: a clone that knows both an encrypted remote
and a plain one holds the decrypted commits of the first and can push them to
the second with one command. Every contact with an encrypted remote (a
clone, a fetch, a push) checks for a pre-push hook running
`git-remote-enc pre-push <remote> <url>` and installs it where none exists,
unless `enc.installHook = false`. A pre-push hook that does not run the guard
(it has to call it itself: `install-hook --chain` inserts the call after
the `#!` line of a shell hook, reading the ref list once and handing it to
the rest of the hook on stdin), a guard that is not executable, or a
`core.hooksPath` directory without one is left alone and reported, on every
contact: another tool (`git lfs install --force`) can replace the guard at
any time. `git-remote-enc install-hook` installs it by hand. The hook refuses a push
that carries content of an encrypted remote the destination does not already
have. "The encrypted remote" is every other remote with an `enc::` URL: its
remote-tracking refs, and the local branches whose upstream it is (they hold
fix commits not pushed yet). "Already has" is the destination's
remote-tracking refs and the old values of the pushed refs.

The test is on content, not history, since backporting a fix by cherry-pick
or squash creates commits the encrypted remote never had. A push is refused
when the objects it would send (commits, trees, blobs; the empty blob and
tree aside) share one with the objects only the encrypted remote has, which
catches a fixed file carried over unchanged; or when one of its commits has
the patch id (`git patch-id --stable`) of an encrypted-only commit, taken
over the diff without context lines, which catches the same change applied
where the lines around it differ; or when one of its hunks adds what a hunk
of an encrypted-only commit adds, whitespace and line breaks aside, which
catches a fix whose removed lines changed in a conflict resolution, or that
was squashed with other edits. Hunks adding under 24 bytes, whitespace
aside, are too common to count (a lone `}`), so a fix that small is matched
only by the first two tests. Any git failure while checking refuses the
push. A fix whose added lines were rewritten, by hand or to resolve a
conflict inside them, matches none.

git chooses the transport from the push URL, so `remote.<name>.pushurl`, or
a `url.<base>.pushInsteadOf` (or `insteadOf`) rule, can send pushes to an
`enc::` remote in clear, to a plain URL, without running the helper. The
guard refuses a push whose remote is configured with an `enc::` URL when the
URL git actually pushes to is not one. The helper cannot see such a push,
but it refuses every other use of that remote (fetch, the subcommands) while
its push URL resolves to a plain one.

Pushing to another encrypted remote is checked the same way, since its
audience differs. The disclosure itself is a deliberate `git push
--no-verify`; once the fix is public and fetched, the guard no longer
matches it. The hook only covers clones where it is installed, and content
that reaches no encrypted ref (a fix written but never pushed to or branched
from the encrypted remote) is invisible to it.

### 6.8 Threat model

**Assets.** The repository's contents and history; its ref names and commit
metadata; the participant and admin lists; the pack keys (which decrypt the
whole history); the participants' private keys; and the integrity of the refs
participants fetch and build on.

**Actors.** Participants: admins, signing participants and `age1…` readers. A
participant removed from the list. The host operator, and anyone with write
access to the hosting repository. Anyone with read access to it. A network
attacker between client and host. A local attacker on a participant's
machine.

**Trust boundaries and data flows.**

```
  participant's machine (trusted)                  │  host (trusted for availability only)
                                                   │
  private keys ───┐                                │
  .git/config ────┼──▶ git-remote-enc ── push ─────┼──▶ backend branch: the signed,
  (participants,  │      │       ▲                 │    encrypted manifest and the
   admins)        │      ▼       └──── fetch ◀─────┼─── encrypted packs (its name and
                  │   $GIT_DIR: decrypted objects, │    the blob sizes are visible)
                  │   trust state (authenticated)  │
                                                   │
  out of band: the other participants' public keys and fingerprints (first contact)
```

The host is trusted for availability only: not to read, not to change what it
stores, not to serve the same view to everyone. The participant's machine is
trusted with everything: private keys, plaintext objects and the local trust
state. The first contact relies on a channel outside both, through which a
participant learns another's public key (and, to bound a rollback or
substitution, the repository id and generation). Git LFS, when a repository uses
it, is a second flow from the machine to the host that bypasses the helper
(5.1).

| Threat | Mitigation | Residual risk |
|---|---|---|
| The host or a host reader reads the repository | age encryption of manifest and packs (4.3, 4.4) | the metadata of section 6.4: branch name, sizes, timing, participant count, key tags |
| The host forges refs or a manifest | a manifest is accepted only when signed by a previously accepted participant (6.1) | none once a manifest has been accepted |
| The host rolls the branch back | strictly increasing `generation`, checked against local state (6.2), or against `enc-minGeneration` on first contact (6.1) | a host can withhold new pushes from a client that never saw them (freeze); a first contact without `enc-minGeneration` accepts any generation its pinned signer signed |
| A participant makes the remote unusable for everyone | a generation over the history's bound is refused (6.2); once the accepted manifest has admins, a list change not signed by one of them is refused (6.1) | a refused manifest at the tip blocks every client until the host restores the branch; the host accepts any push |
| The host serves different views to different clients | a changed manifest for an accepted generation, or a next one not chained to it, is refused (6.2) | detected only by a client that sees both views, and further apart than one generation only by `log` |
| The host substitutes its own remote on first contact | first contact needs a pinned participant list; `enc-repo` pins the repository; repo id lookup across URL spellings (6.1) | `enc.trustOnFirstUse = true` reopens it, by choice, and set in the global config it does so for every remote; without `enc-repo`, another remote signed by a pinned key passes |
| The host deletes or recreates the branch | refused; `forget` needs a human decision (section 9) | availability: protect the branch on the host and keep a mirror; deletion stops work until restored |
| A participant changes who participates | only admins change the lists; a push never does it implicitly (6.1, 6.3) | a remote from before format 2 has no admins until appointed; admins are fully trusted |
| A participant rewrites or deletes refs | every change is signed and kept in the backend history (`log`, 6.6) | no per-ref permission: one remote per audience (section 1) |
| The host inserts forged manifests into the history `log` reads | the `previous` hash chain from the accepted manifest; unchained manifests are marked not verified and do not name their signer (6.6) | manifests from before `previous` existed cannot be verified |
| The host rewrites the backend history, erasing the audit trail | a tip that does not descend from the last one seen is reported, as a participant's repack when a signed `epoch` above the accepted generation says so; `log` flags missing generations (6.6) | the removed manifests are gone unless the branch is protected on the host or mirrored; a first contact after the rewrite gets no warning, only `log`'s |
| A removed participant reads the past | future pack keys are unknown to them (6.3) | they keep the past history; full revocation is a new remote |
| A participant's private key is compromised | passphrase on the key; admins remove the key | the whole readable history is exposed, permanently; no hardware or agent-held keys (6.5) |
| A local attacker rewrites the trust state | HMAC keyed from the user's identity; a file with a wrong or missing tag, or missing while the tracking ref or `<key>.known` exists, is refused (5.4, section 9) | stops tampering without code execution (a restored backup, a synced or shared directory); whoever can write `.git` can run code through hooks instead |
| A participant pushes a hostile git object (a `.git` tree entry) | received objects are fsck-checked by default (5.2) | none with the default; `fetch.fsckObjects = false` disables it |
| A crafted `enc::` URL runs a command | the URL goes to git after `--`, and a leading `-` is refused | none known |
| Secrets leak through tooling | pack keys redacted by default; no passphrase from the environment; secrets wiped from memory (6.5) | swap and core dumps while a secret is live |
| git config reroutes pushes to an encrypted remote to a plain URL (`pushurl`, `pushInsteadOf`) | the pre-push guard refuses it; the helper refuses to fetch from such a remote (6.7) | a clone without the guard pushes in clear; an `insteadOf` that rewrites the fetch URL too never runs the helper at all |
| Git LFS uploads tracked files in clear alongside a push | a push is refused while LFS holds files locally and any pre-push hook but the guard exists (5.1) | `enc-allowLfs` with LFS still pointed at the forge; LFS storage outside the places checked |
| Plaintext leaks through the developer's workflow | a pre-push hook, installed on first contact refuses to push content of an encrypted remote (shared objects, or a cherry-picked change by patch id) to any other remote (6.7) | clones where it could not be installed (an existing hook, `core.hooksPath`: reported on every fetch and push) or was turned off, `--no-verify`, content not yet tied to an encrypted ref, a fix whose added lines were rewritten, a fix adding under 24 bytes whose removed lines changed in a conflict or that was squashed with other edits; the decrypted objects live in the local `$GIT_DIR` (5.4): use a dedicated clone, disk encryption, and delete the clone when done |
| A malicious or compromised build | reproducible builds from pinned inputs, SHA-pinned actions, Sigstore-signed provenance and an SBOM per release, `cargo audit` and `cargo deny` in CI | the build image runs Nix with `sandbox = false`; dependencies include a pre-release crate (`kem`) and an unfixed but unreachable one (`rsa`, RUSTSEC-2023-0071) |
| The host exhausts a client's memory with a huge manifest | manifest blobs over 64 MiB are refused before being read (4.2) | pack blobs are streamed, but the backend fetch itself is unbounded, as with any git fetch |
| A parser bug on untrusted input | Rust with panics denied by lint; the signature is checked before parsing when a signer list is known; mutation tests of every parser (section 10) | no coverage-guided fuzzing; trust on first use parses unauthenticated text |
| Traffic analysis | none (non-goal, section 1) | the host sees who pushes and fetches, when, and how much |

## 7. Performance and growth

- Push cost: `pack-objects` over new objects + one age encryption + one
  incremental `git push`. Fetch cost symmetric. Independent of history length.
- The backend tree grows by one blob per push; git handles trees with tens of
  thousands of entries fine, but a very active repository may want
  **repacking**, `git-remote-enc repack <remote>`: index every pack, pack
  exactly what the manifest refs reach (objects only deleted refs reached are
  dropped) as two packs, and push a new generation listing only them, in a
  tree holding only them and the manifest. The first, the **snapshot**, holds
  the ref tips with their whole trees and no history (`rev-list --objects
  --no-walk`, tags peeled), and the manifest's `snapshot` item names it and
  the commits it holds; the second holds the rest. Neither is thin, and
  together they must hold as many objects as `rev-list --objects` lists, or
  nothing is pushed. Later pushes are thin against the refs, so the snapshot
  and the packs after the history pack usually make a shallow clone; a pack
  or ref that needs objects or commits older than the snapshot (a branch
  forked from an older commit, a delta against an older object) needs the
  history pack too. Participants see an ordinary push, but its pack ids are
  in no other clone's `have`: every other participant's next fetch
  downloads the whole repacked repository. It is explicit, never automatic,
  so a push never surprises anyone with a full re-upload.
- The old blobs stay reachable from the backend history. `repack
  --rewrite-history` makes the new commit descend from none of the old
  history instead (a root, or on top of its own staging chain; a forced update
  the host must allow), sets `epoch` to its generation, and the host reclaims the
  old blobs when it prunes unreachable objects. A client that sees the history
  no longer descend from its last backend commit warns that the host rewrote
  it, unless the new manifest's `epoch` is above the generation it had
  accepted: then a participant did, and says so in a signed manifest. `log`
  starts at the epoch, from which the generation bound counts (section 6.2).
  A participant could already push a rewrite; `epoch` only lets it be told
  apart from the host's.
- Local storage: the decrypted objects, plus commits, trees and manifests of
  the backend branch; pack blobs are dropped once indexed or pushed (5.4).
- Thin packs give cross-push deltas for modified files. Unlike gcrypt, a
  100-byte change to a 1 MB file costs roughly the delta, not 1 MB.

## 8. Configuration

| key | meaning |
|---|---|
| `remote.<name>.enc-identity`, `enc.identity` (multi) | identity files. Default: `user.signingkey` when `gpg.format = ssh` and it is a path, else `~/.ssh/id_ed25519` |
| `remote.<name>.enc-signingkey`, `enc.signingkey` | SSH private key used to sign. Default: the first SSH identity |
| `remote.<name>.enc-participants`, `enc.participants` (multi) | public keys, one per value, or `@<file>` (authorized_keys-style). Required to create a remote; on first contact with an existing remote, the signer must be one of them; on an existing remote a push never applies it (it warns when it differs); `git-remote-enc participants --apply` does (section 6.3) |
| `remote.<name>.enc-admins`, `enc.admins` (multi) | like `enc-participants`, for the admin list: the admins of a new remote (default: its creator), or the list `participants --apply` sets (section 6.1) |
| `remote.<name>.enc-trustOnFirstUse`, `enc.trustOnFirstUse` | boolean, default false. Accept the signer of an unknown remote without a pinned participant list (section 6.1) |
| `remote.<name>.enc-repo`, `enc.repo` | the `repo` id the remote must serve (section 6.1) |
| `remote.<name>.enc-minGeneration`, `enc.minGeneration` | the lowest `generation` accepted (section 6.1) |
| `remote.<name>.enc-installHook`, `enc.installHook` | boolean, default true. Install the pre-push guard where no pre-push hook exists, and report one that does not run it, on every contact (section 6.7) |
| `remote.<name>.enc-allowLfs`, `enc.allowLfs` | boolean, default false. Push although a pre-push hook runs Git LFS, or the pushed commits hold LFS pointers (section 5.1) |
| `remote.<name>.enc-refuseForks`, `enc.refuseForks` | boolean, default true. Refuse a manifest that forks from the accepted one; false accepts it with a warning (section 6.2) |
| `remote.<name>.enc-partSize`, `enc.partSize` | size (`k`, `m`, `g` suffixes), default 1g, at least 16k. Pack blobs larger than this are stored as parts of this size; 0 stores them whole (section 4.4) |
| `remote.<name>.enc-uploadBatch`, `enc.uploadBatch` | size, default 1g. A push whose parts exceed this uploads them in pushes of at most this size ahead of the manifest; 0 sends everything in one push (section 5.1) |
| `fetch.fsckObjects`, `transfer.fsckObjects`, `fetch.fsck.*` | git's own keys; received objects are checked unless one of the first two is false (section 5.2) |

URL: `enc::<any git url>[#<branch>]`. Everything after `enc::` is handed to
git verbatim, so ssh aliases, `https://token@…`, insteadOf rewrites and
credential helpers all work.

### 8.1 Setup commands

They write only the keys of the table above and run the same checks as a
push or fetch, earlier and in one place:

- `init <name> <git-url>` refuses a host that is unreachable (with a hint for
  an scp-style URL without a user) or already has the backend branch, makes
  `~/.ssh/enc_<name>` with `ssh-keygen` unless `--identity` is given, sets the
  identity and participant list (its public key first, read from the key
  file without the passphrase), and installs or chains the guard.
- `invite <remote> [<key>…]` adds the keys as `participants --add` does, then
  prints `join` with the current participant list, `repo` and `generation`:
  the pins of a first contact (section 6.1). They are authentic only if the
  line reaches the joiner over a channel the host does not control.
- `join <name> <git-url> --participant … [--repo] [--min-generation]` writes
  those pins as `enc-participants`, `enc-repo` and `enc-minGeneration`, sets
  up identity and guard, and fetches; on failure it prints the joiner's key to
  send to a participant.
- `participants --add/--remove <remote>` edits `enc-participants` (seeded from
  the remote's list when unset; a list read from `@<file>` is refused), shows
  the difference, asks on the terminal (`--yes` skips) and applies it; a
  refusal restores the previous configuration.
- `doctor <remote>` reports, without installing the guard: the host, the
  identity files, the guard, Git LFS, then the manifest (first-contact and
  local-state refusals included), membership, pending list changes and a
  shallow boundary the remote cannot complete.

## 9. Failure modes and recovery

- **Push interrupted after step 7:** the host has the new commit, the local
  tracking ref is stale. The next connect fetches and reconciles; the pack is
  re-indexed from the blob (its objects are already local, `index-pack` is
  idempotent).
- **Push interrupted before step 7:** nothing on the host changed; the temp
  file is removed by a later run once it is a day old (a younger one may
  belong to a helper still running on the same remote).
- **Repo id changed, or the backend branch vanished:** the remote was recreated
  or deleted, or the host is replacing it. The helper refuses: silently
  accepting would defeat the anti-rollback and trust chain. Participants decide
  on recovery out of band: once they confirm the change, `git-remote-enc
  forget <remote>` removes the local state and the backend repository, and
  the next contact is a first contact, which needs a pinned participant list
  (section 6.1).
- **Local trust state missing or altered:** the trust file is gone while the
  tracking ref or `<key>.known` shows a manifest was accepted, or its tag is
  missing or does not verify. The helper refuses rather than falling back to
  a first contact; recovery is the same `forget`.
- **Not a participant:** age reports no matching key; the helper says so and
  names the identities it tried.
- **Stale lease three times:** give up with a clear message; the user retries.

## 10. Testing

Black-box tests (`crates/git-remote-enc/tests/e2e.rs`) run the real binary
through git against a local bare repository as the "host", with generated
ed25519 keys:

- init, push, clone, fetch round trip; contents identical;
- incremental transfer: bytes received by the host per push are bounded by the
  new objects (asserted via `transfer.unpackLimit=1` and pack sizes);
- non-fast-forward rejected without `--force`, accepted with it;
- concurrent push: a stale lease is retried and no pack is lost;
- a key that is not a participant cannot read; a `age1…` reader can read but
  cannot push; a manifest signed by a non-participant is rejected;
- rollback of the backend branch to an older tip is refused, and so is an
  older or substituted manifest on a first contact pinned with `enc-repo` and
  `enc-minGeneration`;
- a backend history rewritten by the host is reported by fetch and `log`, and
  a forked one is refused;
- a tampered trust file, with or without its tag line, is refused;
- a hostile object (a `.git` tree entry) is refused on fetch;
- a push is refused, before the hook runs, while a pre-push hook runs Git
  LFS, and a push carrying LFS pointers is refused;
- a push that reaches a shallow clone's boundary is refused, unless this
  remote set that boundary;
- `install-hook --chain` runs the guard ahead of an existing hook, which
  still gets the ref list;
- `init`, `invite` and `join` set a remote up end to end, `participants
  --remove` locks a participant out of new pushes, and `doctor` reports a
  foreign hook and state left from a deleted remote;
- the pre-push guard refuses to publish commits of an encrypted remote,
  backports onto diverged code and through a conflict included, and every
  contact reinstalls it when missing or reports it when replaced.

Unit tests cover manifest parsing/serialization, refspec parsing and the trust
rules. Every parser of untrusted input (manifest, envelope, refspec,
participant keys, SSH signatures, the local trust file) also gets thousands
of deterministic mutations of a valid input (`enccore/src/mutate.rs`: bit
flips, insertions, deletions, truncation, duplicated and dropped lines) and
must return an error or a consistent value, never panic. This stands in for
coverage-guided fuzzing, which needs a nightly toolchain the pinned one does
not provide.

## 11. Credits

- Cyrille Mucchietto — security design review

# tdnf - tiny dandified yum

A C implementation of a dnf/yum-compatible package manager built on
`libsolv` and `librpm`, with downloads handled by Zig's HTTP/TLS stack.

## Build

Requires Zig 0.16+ and the following C development packages (Debian/Ubuntu
names; equivalent `*-devel` packages on rpm distros):

```
librpm-dev libexpat1-dev \
libsqlite3-dev libgpgme-dev libpopt-dev liblua5.4-dev pkg-config
```

Then:

```sh
zig build install --prefix ./out
```

This produces `./out/bin/tdnf`, `./out/lib/libtdnf.so.4.0.0` and friends.

Debug build:
```sh
zig build -Doptimize=Debug install --prefix ./out
```

Native Lua scriptlet support (for `<lua>` RPM scriptlets) is enabled by
default, since real base packages in supported distros (Fedora
`bash`/`glibc`/`filesystem`/`setup`, Azure Linux `filesystem`) use
`<lua>`-tagged scriptlets. The default link name is `lua`; on distros
that package the library under another name (for example Debian/
Ubuntu's `liblua5.4-dev`), pass `-Drpmzig-lua-lib=lua5.4`:

```sh
zig build -Drpmzig-lua-lib=lua5.4 install --prefix ./out
```

Disable Lua support entirely with `-Drpmzig-lua=false` (this fails
loudly on any `<lua>`-tagged scriptlet at execution time rather than
silently mis-executing it).

The composed native transaction executor (rpmzig install, rpmdb-write,
file-erase, scriptlet, trigger engines) is the sole transaction-
execution path — every `tdnf install`/`erase`/`upgrade` dispatches
through it. There is no build-time opt-out to librpm's `rpmtsRun`.

## Configuration

Create `tdnf.conf` under `/etc/tdnf/`:

```text
[main]
gpgcheck=1
installonly_limit=3
clean_requirements_on_remove=true
repodir=/etc/yum.repos.d
cachedir=/var/cache/tdnf
```

Place `.repo` files under `/etc/yum.repos.d` (or your `repodir`).

```sh
./out/bin/tdnf list installed
```

## Testing

The pytest suite under `pytests/` exercises the binaries against a
locally-served rpm repo. It requires an rpm-aware host: `rpm`,
`rpmbuild`, `createrepo_c`, and the `python3-pytest`/`python3-requests`/
`python3-pyOpenSSL` stack. With those in place:

```sh
zig build install --prefix ./out
cd pytests && LD_LIBRARY_PATH=../out/lib pytest -v
```

Or use the convenience step:

```sh
zig build check
```

## Static analysis (Coverity)

`ci/coverity.sh` wraps `zig build` with `cov-build`. It generates an
HTML report under `build-coverity/html/`.

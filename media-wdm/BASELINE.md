# media-wdm — current media.30 EOS source

## Authoritative component source

- Component repository: `D:\DroidVM-VPU\01-源码\media-wdm`
- Server: `root@<build-server>`
- Current source: `/srv/media-wdm-tag-eosfix-build/media-wdm`
- Build workspace: `/srv/media-wdm-tag-eosfix-build`
- Baseline tag: `media-1.0.0.30-eosfix-20261101`
- Branch: `master` (local import history; no remote push performed).
- Original remote URL: this component was a directory inside the Windows Rust driver workspace; the build directory itself has no Git metadata. No invented remote is configured.

## Source and binary correspondence

All ten component input files were SHA256-compared to the server EOS source on 2026-11-01. The matching historical local copy was `av1-tag-work/media-wdm-tag-eosfix`, NOT the intermediate `media-wdm-tag` copy.

- `virtio_media.inf`: DriverVer `10/27/2026,1.0.0.30`; SHA256 `89ca380837a543db9eb1e69595b0c238ae0d16d4ec7e155c85276fa6270f04cc`.
- `src/lib.rs`: `9ca4f93d4b306284c9afc179f2ead8b9adf54fe171e97acde40cc3e46e6cd2be`.
- Recorded unsigned SYS: `f2fb5de78405572cae2cecd6dd21a48c176c73761ab906d6c5f0ae9465946526`.
- Signed media.30 SYS in `02-编译产物/tag-1.0.0.30-stage`: `BDAE056CB2D71C09F3799B1B916052EC639626EBC54D13F95E4E316FE03A1EFB`.
- Build command: `cargo +nightly build -p virtio-media-wdm --target aarch64-pc-windows-msvc`, using the server workspace/toolchain and its WDK settings.
- Build/evidence origin before migration: `av1-tag-work/eosfix-artifacts/DELIVERY.md`, `logs/eosfix-build.log`, `logs/eosfix-pdb.txt`. The repository-reorganization migration index records their final locations.

## Changes included

Per-session ownership, tag/timestamp ABI, reduced kernel stack usage, event/progress handling and the final EOS command correction are present in this source. The .30 EOS fix sends the full 72-byte V4L2 decoder command, validates the full response, latches partial-send/STOP failures, subscribes to EOS, preserves LAST flags and recycles empty LAST capture buffers without publishing a false image.

## Historical commits retained

- `be2b8a4` / `baseline-2026-11-01`: old local snapshot.
- `e08ae35` / `server-media-wdm-tag-build-2026-11-01`: intermediate .26 tag-build import. Its earlier description as media.30 was incorrect; retain it as history only.
- Current .30 source comes from `media-wdm-tag-eosfix-build`, not `/srv/mw-zc/media-wdm` or `/srv/media-wdm-tag-build/media-wdm`.

## Build dependency boundary

The component Cargo.toml refers to its parent Rust workspace, WDK crate and microseh dependency. The original complete workspace is on the server at the path above; this repository records the exact component inputs. Dependency source/build instructions are maintained separately from binary WDK libraries and build caches. No compiled artifacts belong in this repository.

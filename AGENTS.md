# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project

Rust library (edition 2024) — OZReport 바이너리 프로토콜 파서/클라이언트. 한국 기업용 리포팅 시스템 프로토콜.

## Commits

- **Conventional Commits** 형식, 영어, 1줄만. description(body) 작성 금지.
- 예: `feat: add retry backoff to client`, `fix: handle null sentinel for DATE type`

## Commands

- `cargo build` / `cargo build --all-features`
- `cargo test` — 전체 단위+통합 테스트
- `cargo test --test integration_test` — 통합 테스트만
- `cargo test test_name` — 단일 테스트
- `cargo test live_fetch -- --ignored` — 실 서버 테스트 (네트워크 필요)
- `cargo clippy --all-features` / `cargo fmt`

## Critical Non-Obvious Patterns

- **Feature flags**: `default = ["client", "gzip"]`. `client` = reqwest/tokio/urlencoding, `gzip` = flate2. 모듈은 `#[cfg(feature = "...")]`으로 게이트됨.
- **고정 프레임**: 모든 요청은 정확히 **9,545바이트** (`REQUEST_FRAME_SIZE`). `BufWriter`가 const generic으로 이 크기를 기본값으로 사용.
- **Big-Endian**: 모든 바이너리 I/O는 Big-Endian.
- **문자열 인코딩 3종**: UTF-16BE (4B char count prefix), Java Modified UTF-8/CESU-8 (2B byte length prefix), OZ UTF (4B i32 byte length prefix). `cesu8` 크레이트 사용 — 표준 UTF-8이 아님.
- **NUMERIC/DECIMAL은 boolean prefix 없음**: 다른 문자열 필드(VARCHAR 등)는 `bool + utf` 패턴이지만, NUMERIC/DECIMAL은 `utf`만 직접 읽음. 빈 문자열 = null.
- **INTEGER/TINYINT null sentinel**: `i32::MIN` (0x80000000)이 null.
- **DATE null 감지**: hi/lo split — `(value >> 16) == i16::MIN && (value & 0xFFFF) == 0`일 때만 null.
- **Binary 빈 값은 lossy**: `Binary(vec![])` → write → read = `Null`. 빈 바이너리와 null 구분 불가.
- **세션 ID "-1905"**: 미인증 상태의 센티넬 값 (`INITIAL_SESSION_ID`).
- **GZIP blocked**: 표준 gzip이 아닌 커스텀 블록 포맷 (4B size header + gzip data per block, 0으로 종료).
- **NaN/Infinity → null**: `FieldValue` → `serde_json::Value` 변환 시 NaN과 Infinity는 JSON null.
- **매직 넘버**: `0x2711`.
- **한국어 문서**: 모든 doc comment와 에러 메시지가 한국어.

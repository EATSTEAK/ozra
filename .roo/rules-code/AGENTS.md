# Project Coding Rules (Non-Obvious Only)

- `BufWriter::new()` = 9,545바이트 고정 프레임 (요청용). 커스텀 크기는 `BufWriter::<N>::with_size()` 사용.
- `write_utf()` / `read_utf()`는 내부에서 `cesu8` 크레이트로 Java Modified UTF-8 변환 — 표준 `String::as_bytes()` 직접 사용 금지.
- 새 SQL 타입 추가 시 `read_field_value()` + `write_field_value()` 양쪽 모두 구현 필수. NUMERIC/DECIMAL처럼 boolean prefix 없는 예외 케이스 주의.
- 새 메시지 타입은 `OzRequest` + `OzResponse` + `OzRequestResponse` trait 3개 모두 구현. `CLASS_NAME`, `TYPE_MARKER`, `TRAILING_MARKER` const 필수.
- `#[cfg(feature = "client")]` / `#[cfg(feature = "gzip")]` 게이트 누락 시 `--no-default-features` 빌드 실패.
- 에러 메시지는 한국어로 작성. `thiserror`의 `#[error("...")]` 안에 한국어 사용.
- `OzError::is_retryable()` — 새 에러 variant 추가 시 retryable 여부 반드시 구현.
- 테스트에서 매크로 활용: `roundtrip_test!`, `overflow_test!`, `eof_test!` (`src/wire.rs` 내 테스트 모듈).

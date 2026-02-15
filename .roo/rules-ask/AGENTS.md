# Project Documentation Rules (Non-Obvious Only)

- 모든 doc comment와 에러 메시지가 한국어. 코드 읽을 때 한국어 문맥 이해 필요.
- `src/wire.rs`가 프로토콜의 기반 — 문자열 인코딩 3종(UTF-16BE, Modified UTF-8, OZ UTF)의 차이를 이해해야 상위 모듈 분석 가능.
- `src/field.rs`의 SQL 타입별 인코딩 규칙이 일관적이지 않음: VARCHAR는 `bool+utf`, NUMERIC은 `utf만`, INTEGER는 `i32 sentinel null`. 타입별로 개별 확인 필수.
- `src/messages/traits.rs`가 메시지 추상화의 핵심 — `OzRequest`/`OzResponse`/`OzRequestResponse` trait 구조.
- `examples/fetch_abeek.rs`가 전체 클라이언트 플로우의 유일한 E2E 예제 (init_session → login → fetch_data_module).
- `src/constants.rs`에 프로토콜 매직넘버, 프레임 크기, 센티넬 값 등 핵심 상수 집중.
- `ErrorCategory`의 코드 범위가 OZ 서버 내부 모듈(CyclePrint, Viewer 등)에 매핑됨 — `src/error.rs` 참조.

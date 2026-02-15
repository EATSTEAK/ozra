# Project Debug Rules (Non-Obvious Only)

- `cargo test test_name -- --nocapture` — println! 출력 확인 시 필수.
- `#[ignore]` 테스트(`live_fetch`)는 실서버 접속 필요 — `cargo test live_fetch -- --ignored`로 실행.
- 바이너리 파싱 오류 디버깅: `BufReader.offset()` 으로 현재 읽기 위치 확인. `set_offset()`으로 특정 위치부터 재파싱 가능.
- 프로토콜 에러 시 `OzError::error_code()` + `ErrorCategory::from_code()` 로 OZ 서버 에러 분류 확인.
- `is_retryable()` 분류가 잘못되면 클라이언트가 무한 재시도하거나 재시도 없이 실패할 수 있음.
- GZIP 블록 형식 문제: `is_gzip_blocked()` 로 커스텀 블록인지 표준 gzip인지 먼저 판별. 첫 4바이트가 양수 i32면 블록 포맷.
- NULL 값 디버깅: INTEGER null = `0x80000000`, DATE null = hi 16bit가 `i16::MIN` & lo 16bit가 0. 일반 값과 혼동하기 쉬움.
- 세션 문제: `session_id()` 가 `"-1905"`이면 미인증 상태. `NotAuthenticated` 에러의 원인.

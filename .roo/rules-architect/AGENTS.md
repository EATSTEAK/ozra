# Project Architecture Rules (Non-Obvious Only)

- **계층 구조**: `wire` (바이너리 I/O) → `types` (공유 타입) → `field` (SQL 필드 코덱) → `messages` (프로토콜 메시지) → `client` (HTTP 세션). 하위 → 상위 방향 의존만 허용.
- **고정 프레임 제약**: 모든 요청이 정확히 9,545바이트. 새 메시지에 필드 추가 시 이 크기 초과 불가 — 프로토콜 스펙 한계.
- **Feature flag 격리**: `client`와 `gzip`은 독립 feature. `--no-default-features` 빌드가 반드시 통과해야 함. 새 모듈 추가 시 게이트 검토 필수.
- **Trait 기반 메시지 확장**: 새 메시지는 `OzRequest` + `OzResponse` + `OzRequestResponse` 3개 trait 구현. 각 trait에 const (`CLASS_NAME`, `TYPE_MARKER`, `TRAILING_MARKER`) 필수.
- **클라이언트 세션 모델**: `RwLock<SessionState>`로 thread-safe. 플로우: `init_session()` → `login()` → `send()`. 인증 전 요청 시 `NotAuthenticated` 에러.
- **재시도 정책**: `RetryPolicy`의 지수 백오프. `OzError::is_retryable()`이 재시도 대상 결정 — 새 에러 추가 시 반드시 분류.
- **인코딩 불일치**: 요청은 UTF-16BE, 응답은 Modified UTF-8 + OZ UTF 혼용. 요청/응답 간 인코딩 대칭이 아님.
- **Lossy 변환 허용**: Binary 빈 값 → null, NaN/Infinity → JSON null. 데이터 손실이 프로토콜 스펙상 의도된 동작.

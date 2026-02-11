//! OZReport 파서의 에러 타입 계층 구조를 정의합니다.
//!
//! 모든 에러는 [`OzError`] enum으로 표현되며, [`thiserror`]를 통해
//! `Display` 및 `Error` 트레이트가 자동 구현됩니다.

/// OZReport 파서의 최상위 에러 타입
///
/// 바이너리 파싱, 문자열 인코딩, 프로토콜 위반, 서버 에러, HTTP/네트워크 에러를 모두 포괄합니다.
/// HTTP/네트워크 에러 변형은 feature `"client"` 활성화 시에만 포함됩니다.
#[derive(Debug, thiserror::Error)]
pub enum OzError {
    /// 표준 I/O 에러 래핑
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// 버퍼 끝에 도달하여 필요한 바이트를 읽을 수 없음
    #[error(
        "unexpected end of buffer at offset {offset}: need {needed} bytes, only {available} remaining"
    )]
    UnexpectedEof {
        offset: usize,
        needed: usize,
        available: usize,
    },

    /// 요청 버퍼 쓰기 시 프레임 크기 초과
    #[error(
        "buffer overflow at offset {offset}: writing {needed} bytes exceeds {limit} byte limit"
    )]
    BufferOverflow {
        offset: usize,
        needed: usize,
        limit: usize,
    },

    /// 매직 넘버 불일치
    #[error("invalid magic number: expected 0x{expected:08X}, got 0x{actual:08X}")]
    InvalidMagic { expected: u32, actual: u32 },

    /// DataModule prefix 검증 실패
    #[error("invalid data module prefix: expected {expected:?}, got {actual:?}")]
    InvalidPrefix { expected: String, actual: String },

    /// 알 수 없는 SQL 타입 코드
    #[error("unknown SQL type code: {code}")]
    UnknownSqlType { code: i32 },

    /// 알 수 없는 필드 종류 (1=Normal, 2=Calculated만 유효)
    #[error("unknown field kind: {kind}, expected 1 or 2")]
    UnknownFieldKind { kind: i32 },

    /// 필드 수가 허용 한도 초과 (DoS 방어)
    #[error("too many fields: {count} exceeds maximum {max}")]
    TooManyFields { count: usize, max: usize },

    /// 바이너리 데이터 크기가 허용 한도 초과 (DoS 방어)
    #[error("binary data too large: {length} bytes exceeds maximum {max}")]
    BinaryTooLarge { length: usize, max: usize },

    /// UTF-16BE 디코딩 실패
    #[error("invalid UTF-16BE at offset {offset}: {detail}")]
    InvalidUtf16 { offset: usize, detail: String },

    /// Java Modified UTF-8 디코딩 실패
    #[error("invalid Modified UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// CESU-8 디코딩 실패
    #[error("invalid CESU-8/Modified UTF-8 encoding")]
    InvalidCesu8,

    /// OZ 서버가 반환한 프로토콜 에러
    #[error("OZ protocol error (code={code}): {message}")]
    ProtocolError { code: i32, message: String },

    /// 로그인 실패 (유효한 세션 ID가 할당되지 않음)
    #[error("login failed: session ID not assigned, got {session_id:?}")]
    LoginFailed { session_id: String },

    /// 인증되지 않은 상태에서 요청 시도
    #[error("not authenticated: must login first")]
    NotAuthenticated,

    /// HTTP 클라이언트 에러 (reqwest 래핑)
    #[cfg(feature = "client")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// 예기치 않은 HTTP 상태 코드
    #[cfg(feature = "client")]
    #[error("unexpected HTTP status: {status}")]
    HttpStatus { status: u16 },
}

/// [`OzError`]를 사용하는 편의 Result 타입 별칭
pub type Result<T> = std::result::Result<T, OzError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let oz_err: OzError = io_err.into();
        assert!(matches!(oz_err, OzError::Io(_)));
        assert!(oz_err.to_string().contains("IO error"));
    }

    #[test]
    fn test_unexpected_eof_display() {
        let err = OzError::UnexpectedEof {
            offset: 100,
            needed: 4,
            available: 2,
        };
        assert_eq!(
            err.to_string(),
            "unexpected end of buffer at offset 100: need 4 bytes, only 2 remaining"
        );
    }

    #[test]
    fn test_buffer_overflow_display() {
        let err = OzError::BufferOverflow {
            offset: 9540,
            needed: 10,
            limit: 9545,
        };
        assert_eq!(
            err.to_string(),
            "buffer overflow at offset 9540: writing 10 bytes exceeds 9545 byte limit"
        );
    }

    #[test]
    fn test_invalid_magic_display() {
        let err = OzError::InvalidMagic {
            expected: 0x00002711,
            actual: 0x00001234,
        };
        assert_eq!(
            err.to_string(),
            "invalid magic number: expected 0x00002711, got 0x00001234"
        );
    }

    #[test]
    fn test_invalid_prefix_display() {
        let err = OzError::InvalidPrefix {
            expected: "OZBINDEDDATAMODULE".to_string(),
            actual: "WRONG_PREFIX".to_string(),
        };
        assert!(err.to_string().contains("OZBINDEDDATAMODULE"));
        assert!(err.to_string().contains("WRONG_PREFIX"));
    }

    #[test]
    fn test_unknown_sql_type_display() {
        let err = OzError::UnknownSqlType { code: 9999 };
        assert_eq!(err.to_string(), "unknown SQL type code: 9999");
    }

    #[test]
    fn test_unknown_field_kind_display() {
        let err = OzError::UnknownFieldKind { kind: 3 };
        assert_eq!(err.to_string(), "unknown field kind: 3, expected 1 or 2");
    }

    #[test]
    fn test_invalid_utf16_display() {
        let err = OzError::InvalidUtf16 {
            offset: 42,
            detail: "unpaired surrogate".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "invalid UTF-16BE at offset 42: unpaired surrogate"
        );
    }

    #[test]
    fn test_invalid_utf8_conversion() {
        let bad_bytes = vec![0xFF, 0xFE];
        let utf8_err = String::from_utf8(bad_bytes).unwrap_err();
        let oz_err: OzError = utf8_err.into();
        assert!(matches!(oz_err, OzError::InvalidUtf8(_)));
    }

    #[test]
    fn test_protocol_error_display() {
        let err = OzError::ProtocolError {
            code: -1,
            message: "access denied".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "OZ protocol error (code=-1): access denied"
        );
    }

    #[test]
    fn test_login_failed_display() {
        let err = OzError::LoginFailed {
            session_id: "-1905".to_string(),
        };
        assert!(err.to_string().contains("-1905"));
        assert!(err.to_string().contains("login failed"));
    }

    #[test]
    fn test_not_authenticated_display() {
        let err = OzError::NotAuthenticated;
        assert_eq!(err.to_string(), "not authenticated: must login first");
    }
}

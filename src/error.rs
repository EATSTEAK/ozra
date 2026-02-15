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

    /// Repository 알 수 없는 상태 코드
    #[error("unknown repository status: {status}")]
    UnknownRepositoryStatus { status: i32 },

    /// Repository 파일을 찾을 수 없음
    #[error("repository file not found: {path}")]
    RepositoryNotFound { path: String },

    /// Repository 응답 파싱 실패
    #[error("failed to parse repository response: {detail}")]
    RepositoryParseError { detail: String },

    /// GZIP 압축 해제 실패
    #[error("decompression failed: {detail}")]
    DecompressionError { detail: String },

    /// GZIP 압축 실패
    #[error("compression failed: {detail}")]
    CompressionError { detail: String },

    /// 필드 값과 SQL 타입이 일치하지 않음
    #[error("type mismatch: SqlType::{sql_type} expects {expected}, got {actual}")]
    TypeMismatch {
        sql_type: String,
        expected: String,
        actual: String,
    },
}

/// [`OzError`]를 사용하는 편의 Result 타입 별칭
pub type Result<T> = std::result::Result<T, OzError>;

/// OZ Report 서버 프로토콜 에러 코드 상수
///
/// OZ 서버가 `OZCPExceptionMessage` 응답으로 반환하는 에러 코드를 정의합니다.
/// 에러 코드는 **카테고리 기본값 + 서브코드** 구조입니다.
///
/// ```text
/// 에러 코드 = 카테고리 기본값 + 서브코드
/// 예: 10101001 = 10100000 (CYCLEPRINT) + 1001
/// ```
///
/// # 카테고리
///
/// | 카테고리 | 기본값 | 설명 |
/// |---|---|---|
/// | CYCLEPRINT | 10100000 | 순환 인쇄 |
/// | PRINTPREVIEW | 10200000 | 인쇄 미리보기 |
/// | EXPORT | 10300000 | 내보내기 |
/// | DIRECTPRINT | 10400000 | 직접 인쇄 |
/// | SERVERPRINT | 10500000 | 서버 인쇄 |
/// | EMAILSEND | 10600000 | 이메일 전송 |
/// | FAXSEND | 10700000 | 팩스 전송 |
/// | VIEWER | 10800000 | 뷰어 |
/// | ARCHIVE | 10900000 | 아카이브 |
/// | FORMDESIGNER | 11000000 | 폼 디자이너 |
pub mod error_codes {
    // ── 카테고리 기본값 ──────────────────────────────────────────────

    /// CYCLEPRINT 카테고리 기본값 (순환 인쇄)
    pub const CYCLEPRINT_BASE: u32 = 10_100_000;
    /// PRINTPREVIEW 카테고리 기본값 (인쇄 미리보기)
    pub const PRINTPREVIEW_BASE: u32 = 10_200_000;
    /// EXPORT 카테고리 기본값 (내보내기)
    pub const EXPORT_BASE: u32 = 10_300_000;
    /// DIRECTPRINT 카테고리 기본값 (직접 인쇄)
    pub const DIRECTPRINT_BASE: u32 = 10_400_000;
    /// SERVERPRINT 카테고리 기본값 (서버 인쇄)
    pub const SERVERPRINT_BASE: u32 = 10_500_000;
    /// EMAILSEND 카테고리 기본값 (이메일 전송)
    pub const EMAILSEND_BASE: u32 = 10_600_000;
    /// FAXSEND 카테고리 기본값 (팩스 전송)
    pub const FAXSEND_BASE: u32 = 10_700_000;
    /// VIEWER 카테고리 기본값 (뷰어)
    pub const VIEWER_BASE: u32 = 10_800_000;
    /// ARCHIVE 카테고리 기본값 (아카이브)
    pub const ARCHIVE_BASE: u32 = 10_900_000;
    /// FORMDESIGNER 카테고리 기본값 (폼 디자이너)
    pub const FORMDESIGNER_BASE: u32 = 11_000_000;

    // ── CYCLEPRINT 서브코드 (10100000) ──────────────────────────────

    /// CYCLEPRINT 서브그룹 1 기본값
    pub const CYCLEPRINT_SUB1_BASE: u32 = 10_101_000;
    /// CYCLEPRINT 에러 코드 1
    pub const CYCLEPRINT_ERR_1: u32 = 10_101_001;
    /// CYCLEPRINT 에러 코드 2
    pub const CYCLEPRINT_ERR_2: u32 = 10_101_002;
    /// CYCLEPRINT 에러 코드 3
    pub const CYCLEPRINT_ERR_3: u32 = 10_101_003;
    /// CYCLEPRINT 에러 코드 4
    pub const CYCLEPRINT_ERR_4: u32 = 10_101_004;
    /// CYCLEPRINT 서브그룹 2 기본값
    pub const CYCLEPRINT_SUB2_BASE: u32 = 10_102_000;
    /// CYCLEPRINT 에러 코드 5
    pub const CYCLEPRINT_ERR_5: u32 = 10_102_001;
    /// CYCLEPRINT 에러 코드 6
    pub const CYCLEPRINT_ERR_6: u32 = 10_102_002;
    /// CYCLEPRINT 에러 코드 7
    pub const CYCLEPRINT_ERR_7: u32 = 10_102_003;
    /// CYCLEPRINT 에러 코드 8
    pub const CYCLEPRINT_ERR_8: u32 = 10_102_004;

    // ── VIEWER 서브코드 (10800000) ──────────────────────────────────

    /// VIEWER 서브그룹 기본값
    pub const VIEWER_SUB_BASE: u32 = 10_801_000;
    /// VIEWER 에러 코드 1
    pub const VIEWER_ERR_1: u32 = 10_801_001;
    /// VIEWER 에러 코드 2
    pub const VIEWER_ERR_2: u32 = 10_801_002;

    // ── 기타 특수 코드 ──────────────────────────────────────────────

    /// 일반 에러 (비표준 범위, 0x601000 — 프로토콜 문서에는 0x600800으로 표기되어 있으나 10진수 값 기준 정확한 hex)
    pub const GENERAL_ERROR_1: u32 = 6_295_552;
    /// 일반 에러 2 (비표준 범위, 0x602000 — 프로토콜 문서에는 0x601800으로 표기되어 있으나 10진수 값 기준 정확한 hex)
    pub const GENERAL_ERROR_2: u32 = 6_299_648;
    /// 특수 에러 코드 기본값
    pub const SPECIAL_BASE: u32 = 909_100;
    /// 특수 에러 1
    pub const SPECIAL_ERR_1: u32 = 909_101;
    /// 특수 에러 2
    pub const SPECIAL_ERR_2: u32 = 909_102;
    /// 특수 에러 3
    pub const SPECIAL_ERR_3: u32 = 909_103;
}

/// OZ 에러 코드의 카테고리 분류
///
/// 에러 코드를 범위별로 분류합니다. [`from_code`](ErrorCategory::from_code)로 에러 코드에서
/// 카테고리를 얻을 수 있습니다.
///
/// # 예시
///
/// ```rust
/// use ozra::error::ErrorCategory;
///
/// let cat = ErrorCategory::from_code(10101001);
/// assert_eq!(cat, ErrorCategory::CyclePrint);
/// assert_eq!(cat.description(), "순환 인쇄 관련");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// 순환 인쇄 관련 에러 (10100000–10199999)
    CyclePrint,
    /// 인쇄 미리보기 관련 에러 (10200000–10299999)
    PrintPreview,
    /// 내보내기 관련 에러 (10300000–10399999)
    Export,
    /// 직접 인쇄 관련 에러 (10400000–10499999)
    DirectPrint,
    /// 서버 인쇄 관련 에러 (10500000–10599999)
    ServerPrint,
    /// 이메일 전송 관련 에러 (10600000–10699999)
    EmailSend,
    /// 팩스 전송 관련 에러 (10700000–10799999)
    FaxSend,
    /// 뷰어 관련 에러 (10800000–10899999)
    Viewer,
    /// 아카이브 관련 에러 (10900000–10999999)
    Archive,
    /// 폼 디자이너 관련 에러 (11000000–11099999)
    FormDesigner,
    /// 일반 에러 (비표준 범위)
    General,
    /// 특수 에러 (909100–909103)
    Special,
    /// 알 수 없는 카테고리
    Unknown,
}

impl ErrorCategory {
    /// 에러 코드에서 카테고리를 판별합니다.
    ///
    /// 에러 코드의 범위를 분석하여 해당하는 [`ErrorCategory`]를 반환합니다.
    /// 알려진 범위에 속하지 않으면 [`ErrorCategory::Unknown`]을 반환합니다.
    ///
    /// # Arguments
    ///
    /// * `code` - 서버가 반환한 에러 코드 (i32, 음수일 수 있음)
    ///
    /// # 예시
    ///
    /// ```rust
    /// use ozra::error::ErrorCategory;
    ///
    /// assert_eq!(ErrorCategory::from_code(10100000), ErrorCategory::CyclePrint);
    /// assert_eq!(ErrorCategory::from_code(10801001), ErrorCategory::Viewer);
    /// assert_eq!(ErrorCategory::from_code(909101), ErrorCategory::Special);
    /// assert_eq!(ErrorCategory::from_code(-1), ErrorCategory::Unknown);
    /// ```
    pub fn from_code(code: i32) -> Self {
        if code < 0 {
            return Self::Unknown;
        }
        let code = code as u32;
        match code {
            // 특수 에러 범위
            909_100..=909_103 => Self::Special,
            // 일반 에러 (비표준 범위)
            6_295_552 | 6_299_648 => Self::General,
            // 카테고리별 범위 (100,000 단위)
            10_100_000..=10_199_999 => Self::CyclePrint,
            10_200_000..=10_299_999 => Self::PrintPreview,
            10_300_000..=10_399_999 => Self::Export,
            10_400_000..=10_499_999 => Self::DirectPrint,
            10_500_000..=10_599_999 => Self::ServerPrint,
            10_600_000..=10_699_999 => Self::EmailSend,
            10_700_000..=10_799_999 => Self::FaxSend,
            10_800_000..=10_899_999 => Self::Viewer,
            10_900_000..=10_999_999 => Self::Archive,
            11_000_000..=11_099_999 => Self::FormDesigner,
            _ => Self::Unknown,
        }
    }

    /// 카테고리의 한국어 설명을 반환합니다.
    pub fn description(&self) -> &'static str {
        match self {
            Self::CyclePrint => "순환 인쇄 관련",
            Self::PrintPreview => "인쇄 미리보기 관련",
            Self::Export => "내보내기 관련",
            Self::DirectPrint => "직접 인쇄 관련",
            Self::ServerPrint => "서버 인쇄 관련",
            Self::EmailSend => "이메일 전송 관련",
            Self::FaxSend => "팩스 전송 관련",
            Self::Viewer => "뷰어 관련",
            Self::Archive => "아카이브 관련",
            Self::FormDesigner => "폼 디자이너 관련",
            Self::General => "일반 에러 (비표준)",
            Self::Special => "특수 에러",
            Self::Unknown => "알 수 없는 에러",
        }
    }

    /// 카테고리의 기본값(base code)을 반환합니다.
    ///
    /// [`General`](ErrorCategory::General), [`Special`](ErrorCategory::Special),
    /// [`Unknown`](ErrorCategory::Unknown)은 `None`을 반환합니다.
    pub fn base_code(&self) -> Option<u32> {
        match self {
            Self::CyclePrint => Some(error_codes::CYCLEPRINT_BASE),
            Self::PrintPreview => Some(error_codes::PRINTPREVIEW_BASE),
            Self::Export => Some(error_codes::EXPORT_BASE),
            Self::DirectPrint => Some(error_codes::DIRECTPRINT_BASE),
            Self::ServerPrint => Some(error_codes::SERVERPRINT_BASE),
            Self::EmailSend => Some(error_codes::EMAILSEND_BASE),
            Self::FaxSend => Some(error_codes::FAXSEND_BASE),
            Self::Viewer => Some(error_codes::VIEWER_BASE),
            Self::Archive => Some(error_codes::ARCHIVE_BASE),
            Self::FormDesigner => Some(error_codes::FORMDESIGNER_BASE),
            Self::General | Self::Special | Self::Unknown => None,
        }
    }
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl OzError {
    /// 이 에러가 재시도 가능한지 판별합니다.
    ///
    /// 일시적인 네트워크 오류나 서버 과부하(HTTP 5xx) 등은 재시도 가능하고,
    /// 프로토콜 에러, 파싱 에러, 인증 에러 등은 재시도해도 결과가 달라지지 않습니다.
    ///
    /// # 재시도 가능한 에러
    ///
    /// - [`OzError::Http`] — 네트워크 에러 (연결 실패, 타임아웃 등)
    /// - [`OzError::HttpStatus`] — HTTP 5xx 서버 에러
    /// - [`OzError::Io`] — 일부 I/O 에러 (ConnectionReset, TimedOut 등)
    ///
    /// # 재시도 불가능한 에러
    ///
    /// - [`OzError::ProtocolError`] — 서버가 반환한 프로토콜 에러
    /// - [`OzError::NotAuthenticated`] — 인증 필요 (재시도 대신 재인증 필요)
    /// - [`OzError::LoginFailed`] — 로그인 실패
    /// - 파싱 관련 에러들 — 데이터 자체의 문제
    ///
    /// # 예시
    ///
    /// ```rust
    /// use ozra::OzError;
    ///
    /// let err = OzError::Io(std::io::Error::new(
    ///     std::io::ErrorKind::ConnectionReset,
    ///     "connection reset",
    /// ));
    /// assert!(err.is_retryable());
    ///
    /// let err = OzError::NotAuthenticated;
    /// assert!(!err.is_retryable());
    /// ```
    pub fn is_retryable(&self) -> bool {
        match self {
            // I/O 에러: 일시적 오류만 재시도 가능
            Self::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
            ),

            // HTTP 클라이언트 에러: 네트워크 관련 에러는 재시도 가능
            #[cfg(feature = "client")]
            Self::Http(e) => e.is_timeout() || e.is_connect() || e.is_request(),

            // HTTP 상태 코드: 5xx 서버 에러, 408 Request Timeout, 429 Too Many Requests
            #[cfg(feature = "client")]
            Self::HttpStatus { status } => *status >= 500 || *status == 408 || *status == 429,

            // 나머지는 모두 재시도 불가
            _ => false,
        }
    }

    /// `ProtocolError`의 에러 코드에서 [`ErrorCategory`]를 반환합니다.
    ///
    /// `ProtocolError` variant가 아닌 경우 `None`을 반환합니다.
    ///
    /// # 예시
    ///
    /// ```rust
    /// use ozra::error::{OzError, ErrorCategory};
    ///
    /// let err = OzError::ProtocolError {
    ///     code: 10801001,
    ///     message: "viewer error".to_string(),
    /// };
    /// assert_eq!(err.error_category(), Some(ErrorCategory::Viewer));
    ///
    /// let err = OzError::NotAuthenticated;
    /// assert_eq!(err.error_category(), None);
    /// ```
    pub fn error_category(&self) -> Option<ErrorCategory> {
        match self {
            Self::ProtocolError { code, .. } => Some(ErrorCategory::from_code(*code)),
            _ => None,
        }
    }

    /// `ProtocolError`의 에러 코드 값을 반환합니다.
    ///
    /// `ProtocolError` variant가 아닌 경우 `None`을 반환합니다.
    pub fn error_code(&self) -> Option<i32> {
        match self {
            Self::ProtocolError { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// 에러 코드에 대한 사람이 읽을 수 있는 요약 문자열을 생성합니다.
///
/// 에러 코드와 서버 메시지를 결합하여 카테고리 정보가 포함된 설명을 반환합니다.
///
/// # 예시
///
/// ```rust
/// use ozra::error::format_error_detail;
///
/// let detail = format_error_detail(10801001, "file not found");
/// assert!(detail.contains("뷰어"));
/// assert!(detail.contains("10801001"));
/// assert!(detail.contains("file not found"));
/// ```
pub fn format_error_detail(code: i32, message: &str) -> String {
    let category = ErrorCategory::from_code(code);
    format!(
        "[{category}] 에러 코드 {code}: {message}",
        category = category,
        code = code,
        message = message,
    )
}

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

    #[test]
    fn test_unknown_repository_status_display() {
        let err = OzError::UnknownRepositoryStatus { status: 99 };
        assert_eq!(err.to_string(), "unknown repository status: 99");
    }

    #[test]
    fn test_repository_not_found_display() {
        let err = OzError::RepositoryNotFound {
            path: "/CM/missing.ozr".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "repository file not found: /CM/missing.ozr"
        );
    }

    #[test]
    fn test_repository_parse_error_display() {
        let err = OzError::RepositoryParseError {
            detail: "unexpected EOF".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to parse repository response: unexpected EOF"
        );
    }

    #[test]
    fn test_decompression_error_display() {
        let err = OzError::DecompressionError {
            detail: "corrupt data".to_string(),
        };
        assert_eq!(err.to_string(), "decompression failed: corrupt data");
    }

    #[test]
    fn test_compression_error_display() {
        let err = OzError::CompressionError {
            detail: "block too large".to_string(),
        };
        assert_eq!(err.to_string(), "compression failed: block too large");
    }

    // ── 에러 코드 상수 값 검증 ──────────────────────────────────────

    #[test]
    fn test_error_code_category_base_values() {
        assert_eq!(error_codes::CYCLEPRINT_BASE, 10_100_000);
        assert_eq!(error_codes::PRINTPREVIEW_BASE, 10_200_000);
        assert_eq!(error_codes::EXPORT_BASE, 10_300_000);
        assert_eq!(error_codes::DIRECTPRINT_BASE, 10_400_000);
        assert_eq!(error_codes::SERVERPRINT_BASE, 10_500_000);
        assert_eq!(error_codes::EMAILSEND_BASE, 10_600_000);
        assert_eq!(error_codes::FAXSEND_BASE, 10_700_000);
        assert_eq!(error_codes::VIEWER_BASE, 10_800_000);
        assert_eq!(error_codes::ARCHIVE_BASE, 10_900_000);
        assert_eq!(error_codes::FORMDESIGNER_BASE, 11_000_000);
    }

    #[test]
    fn test_error_code_cycleprint_subcodes() {
        assert_eq!(error_codes::CYCLEPRINT_SUB1_BASE, 10_101_000);
        assert_eq!(error_codes::CYCLEPRINT_ERR_1, 10_101_001);
        assert_eq!(error_codes::CYCLEPRINT_ERR_2, 10_101_002);
        assert_eq!(error_codes::CYCLEPRINT_ERR_3, 10_101_003);
        assert_eq!(error_codes::CYCLEPRINT_ERR_4, 10_101_004);
        assert_eq!(error_codes::CYCLEPRINT_SUB2_BASE, 10_102_000);
        assert_eq!(error_codes::CYCLEPRINT_ERR_5, 10_102_001);
        assert_eq!(error_codes::CYCLEPRINT_ERR_6, 10_102_002);
        assert_eq!(error_codes::CYCLEPRINT_ERR_7, 10_102_003);
        assert_eq!(error_codes::CYCLEPRINT_ERR_8, 10_102_004);
    }

    #[test]
    fn test_error_code_viewer_subcodes() {
        assert_eq!(error_codes::VIEWER_SUB_BASE, 10_801_000);
        assert_eq!(error_codes::VIEWER_ERR_1, 10_801_001);
        assert_eq!(error_codes::VIEWER_ERR_2, 10_801_002);
    }

    #[test]
    fn test_error_code_special_codes() {
        assert_eq!(error_codes::GENERAL_ERROR_1, 6_295_552);
        assert_eq!(error_codes::GENERAL_ERROR_2, 6_299_648);
        assert_eq!(error_codes::SPECIAL_BASE, 909_100);
        assert_eq!(error_codes::SPECIAL_ERR_1, 909_101);
        assert_eq!(error_codes::SPECIAL_ERR_2, 909_102);
        assert_eq!(error_codes::SPECIAL_ERR_3, 909_103);
    }

    #[test]
    fn test_error_code_hex_values() {
        // 일반 에러 코드의 16진수 값 검증
        // 참고: 프로토콜 문서의 hex 표기(0x600800, 0x601800)는 근사값이며,
        // JS 소스의 실제 10진수 값이 정확합니다.
        assert_eq!(error_codes::GENERAL_ERROR_1, 6_295_552);
        assert_eq!(error_codes::GENERAL_ERROR_2, 6_299_648);
        // 두 코드의 차이는 4096 (0x1000)
        assert_eq!(
            error_codes::GENERAL_ERROR_2 - error_codes::GENERAL_ERROR_1,
            4096
        );
    }

    #[test]
    fn test_error_code_subcode_offsets() {
        // 서브코드 = 에러코드 - 카테고리 기본값
        assert_eq!(
            error_codes::CYCLEPRINT_ERR_1 - error_codes::CYCLEPRINT_BASE,
            1001
        );
        assert_eq!(
            error_codes::CYCLEPRINT_ERR_5 - error_codes::CYCLEPRINT_BASE,
            2001
        );
        assert_eq!(error_codes::VIEWER_ERR_1 - error_codes::VIEWER_BASE, 1001);
        assert_eq!(error_codes::VIEWER_ERR_2 - error_codes::VIEWER_BASE, 1002);
    }

    // ── ErrorCategory::from_code() 테스트 ───────────────────────────

    #[test]
    fn test_category_from_code_cycleprint() {
        assert_eq!(
            ErrorCategory::from_code(error_codes::CYCLEPRINT_BASE as i32),
            ErrorCategory::CyclePrint
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::CYCLEPRINT_ERR_1 as i32),
            ErrorCategory::CyclePrint
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::CYCLEPRINT_ERR_8 as i32),
            ErrorCategory::CyclePrint
        );
        // 범위 상한 경계
        assert_eq!(
            ErrorCategory::from_code(10_199_999),
            ErrorCategory::CyclePrint
        );
    }

    #[test]
    fn test_category_from_code_all_bases() {
        assert_eq!(
            ErrorCategory::from_code(error_codes::PRINTPREVIEW_BASE as i32),
            ErrorCategory::PrintPreview
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::EXPORT_BASE as i32),
            ErrorCategory::Export
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::DIRECTPRINT_BASE as i32),
            ErrorCategory::DirectPrint
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::SERVERPRINT_BASE as i32),
            ErrorCategory::ServerPrint
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::EMAILSEND_BASE as i32),
            ErrorCategory::EmailSend
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::FAXSEND_BASE as i32),
            ErrorCategory::FaxSend
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::VIEWER_BASE as i32),
            ErrorCategory::Viewer
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::ARCHIVE_BASE as i32),
            ErrorCategory::Archive
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::FORMDESIGNER_BASE as i32),
            ErrorCategory::FormDesigner
        );
    }

    #[test]
    fn test_category_from_code_viewer() {
        assert_eq!(
            ErrorCategory::from_code(error_codes::VIEWER_ERR_1 as i32),
            ErrorCategory::Viewer
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::VIEWER_ERR_2 as i32),
            ErrorCategory::Viewer
        );
    }

    #[test]
    fn test_category_from_code_special() {
        assert_eq!(
            ErrorCategory::from_code(error_codes::SPECIAL_BASE as i32),
            ErrorCategory::Special
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::SPECIAL_ERR_1 as i32),
            ErrorCategory::Special
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::SPECIAL_ERR_3 as i32),
            ErrorCategory::Special
        );
    }

    #[test]
    fn test_category_from_code_general() {
        assert_eq!(
            ErrorCategory::from_code(error_codes::GENERAL_ERROR_1 as i32),
            ErrorCategory::General
        );
        assert_eq!(
            ErrorCategory::from_code(error_codes::GENERAL_ERROR_2 as i32),
            ErrorCategory::General
        );
    }

    #[test]
    fn test_category_from_code_unknown() {
        assert_eq!(ErrorCategory::from_code(0), ErrorCategory::Unknown);
        assert_eq!(ErrorCategory::from_code(1), ErrorCategory::Unknown);
        assert_eq!(ErrorCategory::from_code(999_999), ErrorCategory::Unknown);
        assert_eq!(ErrorCategory::from_code(12_000_000), ErrorCategory::Unknown);
    }

    #[test]
    fn test_category_from_code_negative() {
        assert_eq!(ErrorCategory::from_code(-1), ErrorCategory::Unknown);
        assert_eq!(ErrorCategory::from_code(-999), ErrorCategory::Unknown);
        assert_eq!(ErrorCategory::from_code(i32::MIN), ErrorCategory::Unknown);
    }

    #[test]
    fn test_category_description() {
        assert_eq!(ErrorCategory::CyclePrint.description(), "순환 인쇄 관련");
        assert_eq!(ErrorCategory::Viewer.description(), "뷰어 관련");
        assert_eq!(ErrorCategory::Unknown.description(), "알 수 없는 에러");
        assert_eq!(ErrorCategory::General.description(), "일반 에러 (비표준)");
        assert_eq!(ErrorCategory::Special.description(), "특수 에러");
    }

    #[test]
    fn test_category_display() {
        assert_eq!(format!("{}", ErrorCategory::CyclePrint), "순환 인쇄 관련");
        assert_eq!(format!("{}", ErrorCategory::Viewer), "뷰어 관련");
    }

    #[test]
    fn test_category_base_code() {
        assert_eq!(
            ErrorCategory::CyclePrint.base_code(),
            Some(error_codes::CYCLEPRINT_BASE)
        );
        assert_eq!(
            ErrorCategory::Viewer.base_code(),
            Some(error_codes::VIEWER_BASE)
        );
        assert_eq!(
            ErrorCategory::FormDesigner.base_code(),
            Some(error_codes::FORMDESIGNER_BASE)
        );
        assert_eq!(ErrorCategory::General.base_code(), None);
        assert_eq!(ErrorCategory::Special.base_code(), None);
        assert_eq!(ErrorCategory::Unknown.base_code(), None);
    }

    // ── OzError 통합 메서드 테스트 ──────────────────────────────────

    #[test]
    fn test_oz_error_error_category() {
        let err = OzError::ProtocolError {
            code: error_codes::VIEWER_ERR_1 as i32,
            message: "viewer error".to_string(),
        };
        assert_eq!(err.error_category(), Some(ErrorCategory::Viewer));
    }

    #[test]
    fn test_oz_error_error_category_none_for_non_protocol() {
        assert_eq!(OzError::NotAuthenticated.error_category(), None);
        assert_eq!(
            OzError::DecompressionError {
                detail: "test".into()
            }
            .error_category(),
            None
        );
    }

    #[test]
    fn test_oz_error_error_code() {
        let err = OzError::ProtocolError {
            code: 10_101_001,
            message: "test".to_string(),
        };
        assert_eq!(err.error_code(), Some(10_101_001));
    }

    #[test]
    fn test_oz_error_error_code_none_for_non_protocol() {
        assert_eq!(OzError::NotAuthenticated.error_code(), None);
    }

    // ── format_error_detail 테스트 ──────────────────────────────────

    #[test]
    fn test_format_error_detail_viewer() {
        let detail = format_error_detail(error_codes::VIEWER_ERR_1 as i32, "file not found");
        assert!(detail.contains("뷰어"));
        assert!(detail.contains("10801001"));
        assert!(detail.contains("file not found"));
    }

    #[test]
    fn test_format_error_detail_unknown() {
        let detail = format_error_detail(-1, "access denied");
        assert!(detail.contains("알 수 없는 에러"));
        assert!(detail.contains("-1"));
        assert!(detail.contains("access denied"));
    }

    #[test]
    fn test_format_error_detail_cycleprint() {
        let detail = format_error_detail(error_codes::CYCLEPRINT_ERR_1 as i32, "print failed");
        assert!(detail.contains("순환 인쇄"));
        assert!(detail.contains("10101001"));
    }

    // ── ErrorCategory의 derive 트레이트 검증 ─────────────────────────

    #[test]
    fn test_category_clone_and_copy() {
        let cat = ErrorCategory::Viewer;
        let cat2 = cat; // Copy
        #[allow(clippy::clone_on_copy)]
        let cat3 = cat.clone(); // Clone — 의도적으로 Clone 트레이트 검증
        assert_eq!(cat, cat2);
        assert_eq!(cat, cat3);
    }

    #[test]
    fn test_category_debug() {
        let debug_str = format!("{:?}", ErrorCategory::CyclePrint);
        assert_eq!(debug_str, "CyclePrint");
    }

    #[test]
    fn test_category_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ErrorCategory::Viewer);
        set.insert(ErrorCategory::Viewer); // 중복
        set.insert(ErrorCategory::CyclePrint);
        assert_eq!(set.len(), 2);
    }

    // ── is_retryable 테스트 ──────────────────────────────────────────

    #[test]
    fn test_is_retryable_io_connection_reset() {
        let err = OzError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset",
        ));
        assert!(err.is_retryable());
    }

    #[test]
    fn test_is_retryable_io_connection_aborted() {
        let err = OzError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "connection aborted",
        ));
        assert!(err.is_retryable());
    }

    #[test]
    fn test_is_retryable_io_timed_out() {
        let err = OzError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ));
        assert!(err.is_retryable());
    }

    #[test]
    fn test_is_retryable_io_interrupted() {
        let err = OzError::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "interrupted",
        ));
        assert!(err.is_retryable());
    }

    #[test]
    fn test_is_retryable_io_would_block() {
        let err = OzError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "would block",
        ));
        assert!(err.is_retryable());
    }

    #[test]
    fn test_not_retryable_io_not_found() {
        let err = OzError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_not_retryable_io_permission_denied() {
        let err = OzError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_not_retryable_protocol_error() {
        let err = OzError::ProtocolError {
            code: -1,
            message: "access denied".to_string(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_not_retryable_not_authenticated() {
        assert!(!OzError::NotAuthenticated.is_retryable());
    }

    #[test]
    fn test_not_retryable_login_failed() {
        let err = OzError::LoginFailed {
            session_id: "-1905".to_string(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_not_retryable_unexpected_eof() {
        let err = OzError::UnexpectedEof {
            offset: 0,
            needed: 4,
            available: 0,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_not_retryable_invalid_magic() {
        let err = OzError::InvalidMagic {
            expected: 0x2711,
            actual: 0x0000,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_not_retryable_decompression_error() {
        let err = OzError::DecompressionError {
            detail: "corrupt".to_string(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_not_retryable_repository_not_found() {
        let err = OzError::RepositoryNotFound {
            path: "/test.ozr".to_string(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_not_retryable_type_mismatch() {
        let err = OzError::TypeMismatch {
            sql_type: "VarChar".to_string(),
            expected: "String".to_string(),
            actual: "i32".to_string(),
        };
        assert!(!err.is_retryable());
    }
}

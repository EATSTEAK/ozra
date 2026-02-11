//! OZ 프로토콜에서 사용하는 매직 넘버, 프레임 크기, 마커 상수 등을 정의합니다.

/// OZ 프로토콜 매직 넘버 (0x00002711 = 10001)
pub const MAGIC: u32 = 0x0000_2711;

/// HTTP 클라이언트 User-Agent 문자열
pub const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

/// 공통 헤더 필드의 기본값: "d" 필드
pub const FIELD_D_DEFAULT: &str = "-1";

/// 공통 헤더 필드의 기본값: "r" 필드
pub const FIELD_R_DEFAULT: &str = "1";

/// 공통 헤더 필드의 기본값: "rv" 필드 (268435456 = 0x10000000)
pub const FIELD_RV_DEFAULT: &str = "268435456";

/// 응답 파싱 시 허용되는 최대 필드 수 (DoS 방어)
pub const MAX_FIELD_COUNT: usize = 10_000;

/// 바이너리 필드의 최대 길이 (100MB, DoS 방어)
pub const MAX_BINARY_LENGTH: usize = 100 * 1024 * 1024;

/// DataModule 페이로드 내 서브 매직 (0x00002710 = 10000)
pub const SUB_MAGIC: u32 = 0x0000_2710;

/// 모든 요청의 고정 프레임 크기 (9,545 바이트)
pub const REQUEST_FRAME_SIZE: usize = 9545;

/// DataModule 타입 마커 (`Kn.OVe` = 380 = 0x17C)
pub const DATA_MODULE_TYPE_MARKER: u32 = 0x0000_017C;

/// UserLogin 트레일링 마커 (0xB0 = 176)
pub const LOGIN_TRAILING_MARKER: u32 = 0x0000_00B0;

/// Repository 헤더 마커 (0x100 = 256)
pub const REPO_HEADER_MARKER: u32 = 0x0000_0100;

/// 로그인 전 초기 세션 ID
pub const INITIAL_SESSION_ID: &str = "-1905";

/// 클라이언트 프로토콜 버전
pub const CLIENT_VERSION: &str = "20140527";

/// DataModule prefix 검증 문자열
pub const DATA_MODULE_PREFIX: &str = "OZBINDEDDATAMODULE";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_value() {
        assert_eq!(MAGIC, 10001);
        assert_eq!(MAGIC, 0x2711);
    }

    #[test]
    fn test_sub_magic_value() {
        assert_eq!(SUB_MAGIC, 10000);
        assert_eq!(SUB_MAGIC, 0x2710);
    }

    #[test]
    fn test_request_frame_size() {
        assert_eq!(REQUEST_FRAME_SIZE, 9545);
    }

    #[test]
    fn test_data_module_type_marker() {
        assert_eq!(DATA_MODULE_TYPE_MARKER, 380);
    }

    #[test]
    fn test_login_trailing_marker() {
        assert_eq!(LOGIN_TRAILING_MARKER, 0xB0);
    }

    #[test]
    fn test_repo_header_marker() {
        assert_eq!(REPO_HEADER_MARKER, 0x100);
    }

    #[test]
    fn test_initial_session_id() {
        assert_eq!(INITIAL_SESSION_ID, "-1905");
    }

    #[test]
    fn test_client_version() {
        assert_eq!(CLIENT_VERSION, "20140527");
    }

    #[test]
    fn test_data_module_prefix() {
        assert_eq!(DATA_MODULE_PREFIX, "OZBINDEDDATAMODULE");
    }
}

//! UserLogin 요청/응답 메시지
//!
//! OZ 서버 로그인에 사용되는 메시지 타입입니다.
//!
//! # 예시
//!
//! ```ignore
//! use ozra::messages::login::{LoginRequest, LoginResponse};
//! use ozra::messages::traits::{OzRequest, OzResponse};
//! use ozra::constants::INITIAL_SESSION_ID;
//!
//! // 기본 게스트 로그인
//! let req = LoginRequest::guest();
//! let buf = req.build(INITIAL_SESSION_ID)?;
//!
//! // 커스텀 인증 정보
//! let req = LoginRequest::new("admin", "s3cret");
//! let buf = req.build(INITIAL_SESSION_ID)?;
//! ```

use crate::error::Result;
use crate::messages::traits::{OzRequest, OzRequestResponse, OzResponse};
use crate::types::OzMessageHeader;
use crate::wire::{BufReader, BufWriter};

/// UserLogin 요청
///
/// OZ 서버에 로그인하여 세션 ID를 획득하는 요청입니다.
/// 로그인 시 사용자명/비밀번호가 공통 헤더 필드에 포함됩니다.
#[derive(Debug, Clone)]
pub struct LoginRequest {
    /// 로그인 사용자명
    pub username: String,
    /// 로그인 비밀번호
    pub password: String,
}

impl LoginRequest {
    /// 새 LoginRequest를 생성합니다.
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// 기본 게스트 로그인 요청을 생성합니다.
    pub fn guest() -> Self {
        Self::new("guest", "guest")
    }
}

impl OzRequest for LoginRequest {
    const CLASS_NAME: &'static str =
        "oz.framework.cp.message.repository.OZRepositoryRequestUserLogin";
    const TRAILING_MARKER: Option<u32> = Some(0xB0);

    fn write_payload(&self, _writer: &mut BufWriter) -> Result<()> {
        // Login 요청은 추가 페이로드 없음 (공통 헤더에 username/password 포함)
        Ok(())
    }

    /// 로그인 요청은 커스텀 인증 정보(사용자명/비밀번호)를 공통 헤더에 포함시킵니다.
    fn auth_credentials(&self) -> (&str, &str) {
        (&self.username, &self.password)
    }
}

/// UserLogin 응답
///
/// 로그인 성공 시 서버가 반환하는 응답입니다.
/// 헤더의 `"s"` 필드에서 세션 ID를 추출할 수 있습니다.
#[derive(Debug, Clone)]
pub struct LoginResponse {
    /// 응답 메시지 헤더
    pub header: OzMessageHeader,
    /// 서버가 발급한 세션 ID
    pub session_id: String,
}

impl OzResponse for LoginResponse {
    const CLASS_NAME: &'static str = "UserLogin";

    fn parse_payload(_reader: &mut BufReader, header: OzMessageHeader) -> Result<Self> {
        let session_id = header.session_id().unwrap_or("-1").to_string();

        Ok(Self { header, session_id })
    }
}

impl OzRequestResponse for LoginRequest {
    type Response = LoginResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CLIENT_VERSION, INITIAL_SESSION_ID, MAGIC, REQUEST_FRAME_SIZE};
    use crate::messages::common::parse_header;

    /// 테스트 헬퍼: LoginRequest를 빌드합니다.
    fn build_login(username: &str, password: &str) -> Vec<u8> {
        LoginRequest::new(username, password)
            .build(INITIAL_SESSION_ID)
            .unwrap()
    }

    #[test]
    fn test_login_request_guest() {
        let req = LoginRequest::guest();
        assert_eq!(req.username, "guest");
        assert_eq!(req.password, "guest");
    }

    #[test]
    fn test_login_request_new() {
        let req = LoginRequest::new("admin", "s3cret");
        assert_eq!(req.username, "admin");
        assert_eq!(req.password, "s3cret");
    }

    #[test]
    fn test_login_request_class_name() {
        assert_eq!(
            LoginRequest::CLASS_NAME,
            "oz.framework.cp.message.repository.OZRepositoryRequestUserLogin"
        );
    }

    #[test]
    fn test_login_request_trailing_marker() {
        assert_eq!(LoginRequest::TRAILING_MARKER, Some(0xB0));
    }

    #[test]
    fn test_build_login_request_size() {
        let buf = build_login("guest", "guest");
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_login_request_magic() {
        let buf = build_login("guest", "guest");
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(magic, MAGIC);
    }

    #[test]
    fn test_build_login_request_class_name() {
        let buf = build_login("guest", "guest");
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, LoginRequest::CLASS_NAME);
    }

    #[test]
    fn test_build_login_request_fields() {
        let buf = build_login("guest", "guest");
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let _class_name = reader.read_utf16be().unwrap();
        let field_count = reader.read_u32().unwrap();
        assert_eq!(field_count, 16);

        // 첫 번째 필드: un=guest
        let k = reader.read_utf16be().unwrap();
        let v = reader.read_utf16be().unwrap();
        assert_eq!(k, "un");
        assert_eq!(v, "guest");
    }

    #[test]
    fn test_build_login_request_trailing_marker() {
        let buf = build_login("guest", "guest");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.fields.len(), 16);
        let marker = reader.read_u32().unwrap();
        assert_eq!(marker, LoginRequest::TRAILING_MARKER.unwrap());
    }

    #[test]
    fn test_build_login_request_session_id() {
        let buf = build_login("guest", "guest");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.session_id(), Some(INITIAL_SESSION_ID));
    }

    #[test]
    fn test_build_login_request_custom_credentials() {
        let buf = build_login("admin", "password123");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.get_field("un"), Some("admin"));
        assert_eq!(header.get_field("p"), Some("password123"));
    }

    #[test]
    fn test_roundtrip_login_request() {
        let buf = build_login("guest", "guest");
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.class_name, LoginRequest::CLASS_NAME);
        assert_eq!(header.get_field("un"), Some("guest"));
        assert_eq!(header.get_field("p"), Some("guest"));
        assert_eq!(header.get_field("s"), Some(INITIAL_SESSION_ID));
        assert_eq!(header.get_field("cv"), Some(CLIENT_VERSION));
        assert_eq!(header.get_field("d"), Some("-1"));
        assert_eq!(header.get_field("r"), Some("1"));
        assert_eq!(header.get_field("rv"), Some("65536"));
        assert_eq!(header.fields.len(), 16);
    }
}

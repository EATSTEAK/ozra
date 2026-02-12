//! OZ 프로토콜 메시지의 핵심 trait 정의
//!
//! 모든 요청/응답 메시지 타입은 [`OzRequest`], [`OzResponse`] trait을 구현하여
//! 일관된 직렬화/역직렬화 인터페이스를 제공합니다.

use crate::error::Result;
use crate::types::OzMessageHeader;
use crate::wire::{BufReader, BufWriter};

use super::common::{parse_exception, parse_header, write_common_header};

/// OZ 프로토콜 요청 메시지의 공통 인터페이스
///
/// 모든 요청 메시지 타입은 이 trait을 구현하여
/// 일관된 직렬화 인터페이스를 제공합니다.
///
/// # Associated Constants
///
/// - [`CLASS_NAME`](Self::CLASS_NAME): 서버가 요청 타입을 식별하는 데 사용하는 클래스명
/// - [`TYPE_MARKER`](Self::TYPE_MARKER): 페이로드 시작 부분의 타입 식별자 (선택적)
/// - [`TRAILING_MARKER`](Self::TRAILING_MARKER): 요청 끝의 마커 (선택적)
///
/// # 예시
///
/// ```ignore
/// use ozra::messages::OzRequest;
///
/// struct MyRequest { /* ... */ }
///
/// impl OzRequest for MyRequest {
///     const CLASS_NAME: &'static str = "oz.framework.cp.message.MyRequest";
///     const TYPE_MARKER: Option<u32> = Some(0x200);
///
///     fn write_payload(&self, writer: &mut BufWriter) -> Result<()> {
///         // 메시지별 페이로드 직렬화
///         Ok(())
///     }
/// }
/// ```
pub trait OzRequest: Sized {
    /// 요청 클래스명 (서버가 요청 타입을 식별하는 데 사용)
    const CLASS_NAME: &'static str;

    /// 요청 타입 마커 (페이로드 시작 부분의 식별자)
    /// 마커가 없는 요청은 None
    const TYPE_MARKER: Option<u32> = None;

    /// 요청 후 trailing marker (예: Login의 0xB0)
    const TRAILING_MARKER: Option<u32> = None;

    /// 요청 페이로드를 직렬화합니다.
    ///
    /// 공통 헤더 이후에 기록되는 메시지별 페이로드를 작성합니다.
    fn write_payload(&self, writer: &mut BufWriter) -> Result<()>;

    /// 완전한 요청 바이너리를 빌드합니다.
    ///
    /// 공통 헤더 + 타입 마커 + 페이로드 + trailing marker를 모두 포함합니다.
    ///
    /// # Arguments
    ///
    /// * `session_id` - 세션 ID (로그인 전에는 [`INITIAL_SESSION_ID`](crate::constants::INITIAL_SESSION_ID))
    ///
    /// # Returns
    ///
    /// 직렬화된 요청 바이너리 (고정 크기 9,545 바이트)
    fn build(&self, session_id: &str) -> Result<Vec<u8>> {
        let mut writer = BufWriter::new();

        // 공통 헤더 작성
        write_common_header(&mut writer, Self::CLASS_NAME, session_id)?;

        // 타입 마커 (있는 경우)
        if let Some(marker) = Self::TYPE_MARKER {
            writer.write_u32(marker)?;
        }

        // 페이로드
        self.write_payload(&mut writer)?;

        // Trailing marker (있는 경우)
        if let Some(marker) = Self::TRAILING_MARKER {
            writer.write_u32(marker)?;
        }

        Ok(writer.into_bytes())
    }
}

/// OZ 프로토콜 응답 메시지의 공통 인터페이스
///
/// 모든 응답 메시지 타입은 이 trait을 구현하여
/// 일관된 역직렬화 인터페이스를 제공합니다.
///
/// # Associated Constants
///
/// - [`CLASS_NAME`](Self::CLASS_NAME): 이 타입이 처리하는 응답 클래스명
/// - [`EXCEPTION_PATTERN`](Self::EXCEPTION_PATTERN): 에러 응답 감지용 패턴
///
/// # 예시
///
/// ```ignore
/// use ozra::messages::OzResponse;
/// use ozra::types::OzMessageHeader;
///
/// struct MyResponse {
///     header: OzMessageHeader,
///     data: String,
/// }
///
/// impl OzResponse for MyResponse {
///     const CLASS_NAME: &'static str = "MyResponse";
///
///     fn parse_payload(reader: &mut BufReader, header: OzMessageHeader) -> Result<Self> {
///         let data = reader.read_utf16be()?;
///         Ok(Self { header, data })
///     }
/// }
/// ```
pub trait OzResponse: Sized {
    /// 응답 클래스명 (이 타입이 처리하는 응답 식별)
    const CLASS_NAME: &'static str;

    /// 예외 응답 클래스명 패턴 (에러 감지용)
    const EXCEPTION_PATTERN: &'static str = "ExceptionMessage";

    /// 응답 페이로드를 역직렬화합니다.
    ///
    /// 헤더 이후의 페이로드 부분을 파싱합니다.
    ///
    /// # Arguments
    ///
    /// * `reader` - 페이로드 데이터를 읽을 BufReader
    /// * `header` - 이미 파싱된 메시지 헤더
    fn parse_payload(reader: &mut BufReader, header: OzMessageHeader) -> Result<Self>;

    /// 완전한 응답 바이너리를 파싱합니다.
    ///
    /// 헤더 파싱 + 에러 체크 + 페이로드 파싱을 수행합니다.
    ///
    /// # Errors
    ///
    /// - [`OzError::InvalidMagic`](crate::error::OzError::InvalidMagic): 매직 넘버 불일치
    /// - [`OzError::ProtocolError`](crate::error::OzError::ProtocolError): 서버가 에러 응답을 반환
    fn parse(buf: &[u8]) -> Result<Self> {
        let mut reader = BufReader::new(buf);
        let header = parse_header(&mut reader)?;

        // 에러 응답 체크
        if header.class_name.contains(Self::EXCEPTION_PATTERN) {
            return Err(parse_exception(&mut reader)?);
        }

        Self::parse_payload(&mut reader, header)
    }

    /// 이 응답 타입이 주어진 클래스명을 처리할 수 있는지 확인합니다.
    fn can_handle(class_name: &str) -> bool {
        class_name.contains(Self::CLASS_NAME)
    }
}

/// 요청-응답 페어를 정의하는 trait
///
/// 특정 요청 타입에 대응하는 응답 타입을 연결합니다.
/// 이를 통해 제네릭 클라이언트 메서드에서 타입 안전하게
/// 요청-응답 쌍을 처리할 수 있습니다.
///
/// # 예시
///
/// ```ignore
/// use ozra::messages::{OzRequest, OzResponse, OzRequestResponse};
///
/// struct LoginRequest { /* ... */ }
/// struct LoginResponse { /* ... */ }
///
/// impl OzRequest for LoginRequest { /* ... */ }
/// impl OzResponse for LoginResponse { /* ... */ }
///
/// impl OzRequestResponse for LoginRequest {
///     type Response = LoginResponse;
/// }
///
/// // 클라이언트에서 사용:
/// // let response: LoginResponse = client.send(&login_request).await?;
/// ```
pub trait OzRequestResponse: OzRequest {
    /// 이 요청에 대응하는 응답 타입
    type Response: OzResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{MAGIC, REQUEST_FRAME_SIZE};

    /// 테스트용 간단한 요청 구조체
    struct TestRequest {
        value: u32,
    }

    impl OzRequest for TestRequest {
        const CLASS_NAME: &'static str = "test.TestRequest";
        const TYPE_MARKER: Option<u32> = Some(0x1234);
        const TRAILING_MARKER: Option<u32> = Some(0x5678);

        fn write_payload(&self, writer: &mut BufWriter) -> Result<()> {
            writer.write_u32(self.value)
        }
    }

    /// 테스트용 마커 없는 요청 구조체
    struct SimpleRequest;

    impl OzRequest for SimpleRequest {
        const CLASS_NAME: &'static str = "test.SimpleRequest";

        fn write_payload(&self, _writer: &mut BufWriter) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_request_class_name() {
        assert_eq!(TestRequest::CLASS_NAME, "test.TestRequest");
        assert_eq!(SimpleRequest::CLASS_NAME, "test.SimpleRequest");
    }

    #[test]
    fn test_request_markers() {
        assert_eq!(TestRequest::TYPE_MARKER, Some(0x1234));
        assert_eq!(TestRequest::TRAILING_MARKER, Some(0x5678));
        assert_eq!(SimpleRequest::TYPE_MARKER, None);
        assert_eq!(SimpleRequest::TRAILING_MARKER, None);
    }

    #[test]
    fn test_request_build_size() {
        let req = TestRequest { value: 42 };
        let buf = req.build("-1905").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_request_build_magic() {
        let req = TestRequest { value: 42 };
        let buf = req.build("-1905").unwrap();
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(magic, MAGIC);
    }

    #[test]
    fn test_simple_request_build() {
        let req = SimpleRequest;
        let buf = req.build("session123").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_response_exception_pattern_default() {
        struct DummyResponse;
        impl OzResponse for DummyResponse {
            const CLASS_NAME: &'static str = "Dummy";
            fn parse_payload(_: &mut BufReader, _: OzMessageHeader) -> Result<Self> {
                Ok(DummyResponse)
            }
        }
        assert_eq!(DummyResponse::EXCEPTION_PATTERN, "ExceptionMessage");
    }

    #[test]
    fn test_response_can_handle() {
        struct TestResponse;
        impl OzResponse for TestResponse {
            const CLASS_NAME: &'static str = "TestResponse";
            fn parse_payload(_: &mut BufReader, _: OzMessageHeader) -> Result<Self> {
                Ok(TestResponse)
            }
        }

        assert!(TestResponse::can_handle("oz.framework.TestResponse"));
        assert!(TestResponse::can_handle("TestResponseMessage"));
        assert!(!TestResponse::can_handle("OtherResponse"));
    }
}

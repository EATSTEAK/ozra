//! Repository 요청/응답 메시지
//!
//! OZ 서버에서 .ozr/.odi 파일을 다운로드하는 메시지 타입입니다.
//!
//! # 구조체 개요
//!
//! - [`RepositoryRequest`] — 기본 요청
//! - [`RepositoryRequestOptions`] — 확장 요청 옵션 (리프레시, 압축 등)
//! - [`RepositoryResponse`] — 응답 (헤더 + raw 바이트 + 구조화된 상태/항목)
//! - [`RepositoryStatus`] — 파일 상태 (Ready, Loading, Complete, Error)
//! - [`RepositoryContentType`] — 컨텐츠 타입 (Report, DataInterface, Image, Unknown)
//! - [`RepositoryItem`] — 파일 항목 메타데이터
//!
//! # 예시
//!
//! ```ignore
//! use ozra::messages::{RepositoryRequest, OzRequest};
//! use ozra::messages::repository::{RepositoryRequestOptions, RepositoryStatus};
//!
//! // 기본 요청
//! let req = RepositoryRequest::new("/CM/report.ozr");
//! let buf = req.build("session123")?;
//!
//! // 확장 옵션으로 요청
//! let options = RepositoryRequestOptions {
//!     refresh: true,
//!     compressed: false,
//!     extra_info: String::new(),
//! };
//! ```

use crate::error::{OzError, Result};
use crate::messages::traits::{OzRequest, OzRequestResponse, OzResponse};
use crate::types::OzMessageHeader;
use crate::wire::{BufReader, BufWriter};

// ---------------------------------------------------------------------------
// RepositoryStatus
// ---------------------------------------------------------------------------

/// Repository 파일 상태
///
/// 서버가 반환하는 파일의 현재 상태를 나타냅니다.
///
/// # 와이어 포맷
///
/// `i32` 값으로 인코딩되며, [`TryFrom<i32>`] 구현을 통해 변환합니다.
///
/// # 예시
///
/// ```
/// use ozra::messages::repository::RepositoryStatus;
///
/// let status = RepositoryStatus::try_from(2).unwrap();
/// assert_eq!(status, RepositoryStatus::Complete);
///
/// let default_status = RepositoryStatus::default();
/// assert_eq!(default_status, RepositoryStatus::Ready);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
#[derive(Default)]
pub enum RepositoryStatus {
    /// 초기/준비 상태
    #[default]
    Ready = 0,
    /// 로딩 중
    Loading = 1,
    /// 완료
    Complete = 2,
    /// 오류
    Error = -1,
}

impl TryFrom<i32> for RepositoryStatus {
    type Error = OzError;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Loading),
            2 => Ok(Self::Complete),
            -1 => Ok(Self::Error),
            _ => Err(OzError::UnknownRepositoryStatus { status: value }),
        }
    }
}

// ---------------------------------------------------------------------------
// RepositoryContentType
// ---------------------------------------------------------------------------

/// Repository 컨텐츠 타입
///
/// 파일 확장자 기반으로 결정됩니다.
///
/// # 예시
///
/// ```
/// use ozra::messages::repository::RepositoryContentType;
///
/// assert_eq!(RepositoryContentType::from_path("/CM/report.ozr"), RepositoryContentType::Report);
/// assert_eq!(RepositoryContentType::from_path("/CM/data.odi"), RepositoryContentType::DataInterface);
/// assert_eq!(RepositoryContentType::from_path("/img/logo.png"), RepositoryContentType::Image);
/// assert_eq!(RepositoryContentType::from_path("/other/file.txt"), RepositoryContentType::Unknown);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepositoryContentType {
    /// OZ 리포트 파일 (.ozr)
    Report,
    /// OZ 데이터 인터페이스 파일 (.odi)
    DataInterface,
    /// 이미지 파일 (.png, .jpg, .jpeg, .gif)
    Image,
    /// 기타/알 수 없음
    Unknown,
}

impl RepositoryContentType {
    /// 파일 경로에서 컨텐츠 타입을 추론합니다.
    ///
    /// 경로의 확장자를 기반으로 타입을 결정하며, 대소문자를 구분하지 않습니다.
    pub fn from_path(path: &str) -> Self {
        let lower = path.to_lowercase();
        if lower.ends_with(".ozr") {
            Self::Report
        } else if lower.ends_with(".odi") {
            Self::DataInterface
        } else if lower.ends_with(".png")
            || lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.ends_with(".gif")
        {
            Self::Image
        } else {
            Self::Unknown
        }
    }
}

// ---------------------------------------------------------------------------
// RepositoryItem
// ---------------------------------------------------------------------------

/// Repository 응답 항목
///
/// 성공 시 파일 컨텐츠와 메타데이터를 포함합니다.
///
/// # 필드 설명
///
/// - [`path`](Self::path): 요청한 파일 경로
/// - [`content_type`](Self::content_type): 파일 확장자 기반 컨텐츠 타입
/// - [`content`](Self::content): 파일 바이너리 데이터
/// - [`size`](Self::size): 컨텐츠 크기 (바이트)
/// - [`compressed`](Self::compressed): 압축 여부
/// - [`metadata`](Self::metadata): 서버 메타데이터 (키-값 쌍)
#[derive(Debug, Clone)]
pub struct RepositoryItem {
    /// 요청한 파일 경로
    pub path: String,
    /// 파일 MIME 타입 (확장자 기반 추정)
    pub content_type: RepositoryContentType,
    /// 파일 컨텐츠 (raw bytes)
    pub content: Vec<u8>,
    /// 파일 크기 (bytes)
    pub size: usize,
    /// 압축 여부
    pub compressed: bool,
    /// 서버 메타데이터 (key-value)
    pub metadata: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// RepositoryRequestOptions
// ---------------------------------------------------------------------------

/// Repository 요청 옵션
///
/// 기본값을 사용하려면 [`Default::default()`]를 사용하세요.
///
/// # 예시
///
/// ```
/// use ozra::messages::repository::RepositoryRequestOptions;
///
/// let default_opts = RepositoryRequestOptions::default();
/// assert!(!default_opts.refresh);
/// assert!(!default_opts.compressed);
/// assert!(default_opts.extra_info.is_empty());
///
/// let custom_opts = RepositoryRequestOptions {
///     refresh: true,
///     compressed: true,
///     extra_info: "metadata".to_string(),
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct RepositoryRequestOptions {
    /// 리프레시 플래그 — 캐시 우회 여부
    pub refresh: bool,
    /// 압축 플래그 — 응답 압축 요청
    pub compressed: bool,
    /// 추가 정보 — 서버에 전달할 메타데이터
    pub extra_info: String,
}

// ---------------------------------------------------------------------------
// RepositoryRequest
// ---------------------------------------------------------------------------

/// Repository 요청
///
/// OZ 서버에서 리포지토리 파일(.ozr, .odi)을 다운로드하는 요청입니다.
///
/// # 페이로드 구조
///
/// ```text
/// TYPE_MARKER (0x100)           — OzRequest trait에서 자동 작성
/// bool(false)                   — 1B
/// UTF-16BE(extra_info)          — 빈 문자열 (4B 길이 + 0)
/// u32(1)                        — 항목 수
/// UTF-16BE(path)                — 파일 경로
/// i64(0)                        — 타임스탬프 (0 = 없음)
/// bool(compressed)              — 압축 요청 여부
/// bool(refresh)                 — 캐시 우회 여부
/// ```
#[derive(Debug, Clone)]
pub struct RepositoryRequest {
    /// 리포지토리 파일 경로 (예: `"/CM/report.ozr"`)
    pub path: String,
    /// 요청 옵션 (리프레시, 압축, 추가 정보)
    pub options: RepositoryRequestOptions,
}

impl RepositoryRequest {
    /// 새 RepositoryRequest를 기본 옵션으로 생성합니다.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            options: RepositoryRequestOptions::default(),
        }
    }

    /// 옵션을 지정하여 새 RepositoryRequest를 생성합니다.
    pub fn with_options(path: &str, options: RepositoryRequestOptions) -> Self {
        Self {
            path: path.to_string(),
            options,
        }
    }
}

impl OzRequest for RepositoryRequest {
    const CLASS_NAME: &'static str = "oz.framework.cp.message.repositoryex.OZRepositoryRequestItem";
    const TYPE_MARKER: Option<u32> = Some(0x100);

    fn write_payload(&self, writer: &mut BufWriter) -> Result<()> {
        writer.write_bool(false)?;
        // extraInfo (빈 문자열)
        writer.write_utf16be(&self.options.extra_info)?;
        // 항목 수
        writer.write_u32(1)?;
        // 파일 경로
        writer.write_utf16be(&self.path)?;
        // 타임스탬프 (Int64)
        writer.write_i64(0)?;
        // 압축 여부
        writer.write_bool(self.options.compressed)?;
        // 리프레시 여부
        writer.write_bool(self.options.refresh)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RepositoryResponse
// ---------------------------------------------------------------------------

/// Repository 응답
///
/// 서버가 반환한 리포지토리 파일 데이터입니다.
///
/// ## 하위 호환성
///
/// [`data`](Self::data) 필드는 raw 바이트를 그대로 포함하여 기존 코드와의 호환성을 유지합니다.
/// [`status`](Self::status)와 [`item`](Self::item) 필드는 구조화된 응답 데이터를 제공합니다.
///
/// ## 예시
///
/// ```ignore
/// let response: RepositoryResponse = client.send(&req).await?;
///
/// // 기존 방식: raw 바이트 접근
/// println!("Raw data: {} bytes", response.data.len());
///
/// // 새로운 방식: 구조화된 접근
/// if response.status == RepositoryStatus::Complete {
///     if let Some(item) = &response.item {
///         println!("File: {}, type: {:?}", item.path, item.content_type);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RepositoryResponse {
    /// 응답 메시지 헤더
    pub header: OzMessageHeader,
    /// 파일 데이터 (raw 바이트) — 기존 호환성 유지
    pub data: Vec<u8>,
    /// 파일 상태
    pub status: RepositoryStatus,
    /// 파일 항목 (구조화된 메타데이터 포함)
    pub item: Option<RepositoryItem>,
}

impl OzResponse for RepositoryResponse {
    const CLASS_NAME: &'static str = "OZRepositoryResponseItem";

    fn parse_payload(reader: &mut BufReader, header: OzMessageHeader) -> Result<Self> {
        // Repository 응답은 헤더 이후의 나머지를 raw 바이트로 가져옴
        let remaining = reader.remaining();
        let data = if remaining > 0 {
            reader.read_bytes(remaining)?.to_vec()
        } else {
            Vec::new()
        };

        // 현재는 raw 파싱만 수행; status와 item은 기본값
        // 추후 parse_repository_response에서 구조화된 파싱 구현 예정
        Ok(Self {
            header,
            data,
            status: RepositoryStatus::default(),
            item: None,
        })
    }
}

impl OzRequestResponse for RepositoryRequest {
    type Response = RepositoryResponse;
}

/// 호환성 함수: Repository 요청 바이너리를 빌드합니다.
///
/// [`RepositoryRequest`]의 편의 래퍼입니다.
///
/// # 예시
///
/// ```
/// use ozra::messages::repository::build_repository_request;
/// use ozra::constants::REQUEST_FRAME_SIZE;
///
/// let buf = build_repository_request("/CM/test.ozr", "12345").unwrap();
/// assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
/// ```
pub fn build_repository_request(path: &str, session_id: &str) -> Result<Vec<u8>> {
    let req = RepositoryRequest::new(path);
    req.build(session_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{REPO_HEADER_MARKER, REQUEST_FRAME_SIZE};
    use crate::messages::common::parse_header;

    // -- RepositoryRequest tests --

    #[test]
    fn test_repository_request_new() {
        let req = RepositoryRequest::new("/CM/test.ozr");
        assert_eq!(req.path, "/CM/test.ozr");
    }

    #[test]
    fn test_repository_request_class_name() {
        assert_eq!(
            RepositoryRequest::CLASS_NAME,
            "oz.framework.cp.message.repositoryex.OZRepositoryRequestItem"
        );
    }

    #[test]
    fn test_repository_request_type_marker() {
        assert_eq!(RepositoryRequest::TYPE_MARKER, Some(0x100));
    }

    #[test]
    fn test_build_repository_request_size() {
        let buf = build_repository_request("/CM/test.ozr", "12345").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_repository_request_class_name() {
        let buf = build_repository_request("/CM/test.ozr", "12345").unwrap();
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, RepositoryRequest::CLASS_NAME);
    }

    #[test]
    fn test_build_repository_request_payload() {
        let buf = build_repository_request("/CM/test.ozr", "session123").unwrap();
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.get_field("s"), Some("session123"));

        // Repository payload
        let marker = reader.read_u32().unwrap();
        assert_eq!(marker, REPO_HEADER_MARKER);
        let _bool_false = reader.read_bool().unwrap();
        assert!(!_bool_false);
        let extra_info = reader.read_utf16be().unwrap();
        assert_eq!(extra_info, "");
        let item_count = reader.read_u32().unwrap();
        assert_eq!(item_count, 1);
        let path = reader.read_utf16be().unwrap();
        assert_eq!(path, "/CM/test.ozr");
        let timestamp = reader.read_i64().unwrap();
        assert_eq!(timestamp, 0);
        let compressed = reader.read_bool().unwrap();
        assert!(!compressed);
        let refresh = reader.read_bool().unwrap();
        assert!(!refresh);
    }

    #[test]
    fn test_roundtrip_repository_request() {
        let buf = build_repository_request("/CM/report.ozr", "sess42").unwrap();
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.class_name, RepositoryRequest::CLASS_NAME);
        assert_eq!(header.get_field("s"), Some("sess42"));
    }

    // -- RepositoryStatus tests --

    #[test]
    fn test_repository_status_try_from_valid() {
        assert_eq!(
            RepositoryStatus::try_from(0).unwrap(),
            RepositoryStatus::Ready
        );
        assert_eq!(
            RepositoryStatus::try_from(1).unwrap(),
            RepositoryStatus::Loading
        );
        assert_eq!(
            RepositoryStatus::try_from(2).unwrap(),
            RepositoryStatus::Complete
        );
        assert_eq!(
            RepositoryStatus::try_from(-1).unwrap(),
            RepositoryStatus::Error
        );
    }

    #[test]
    fn test_repository_status_try_from_invalid() {
        let result = RepositoryStatus::try_from(99);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OzError::UnknownRepositoryStatus { status: 99 }
        ));
    }

    #[test]
    fn test_repository_status_repr_values() {
        assert_eq!(RepositoryStatus::Ready as i32, 0);
        assert_eq!(RepositoryStatus::Loading as i32, 1);
        assert_eq!(RepositoryStatus::Complete as i32, 2);
        assert_eq!(RepositoryStatus::Error as i32, -1);
    }

    #[test]
    fn test_repository_status_default() {
        assert_eq!(RepositoryStatus::default(), RepositoryStatus::Ready);
    }

    // -- RepositoryContentType tests --

    #[test]
    fn test_content_type_from_path_report() {
        assert_eq!(
            RepositoryContentType::from_path("/CM/report.ozr"),
            RepositoryContentType::Report
        );
        assert_eq!(
            RepositoryContentType::from_path("/CM/REPORT.OZR"),
            RepositoryContentType::Report
        );
    }

    #[test]
    fn test_content_type_from_path_data_interface() {
        assert_eq!(
            RepositoryContentType::from_path("/CM/data.odi"),
            RepositoryContentType::DataInterface
        );
        assert_eq!(
            RepositoryContentType::from_path("/CM/DATA.ODI"),
            RepositoryContentType::DataInterface
        );
    }

    #[test]
    fn test_content_type_from_path_image() {
        assert_eq!(
            RepositoryContentType::from_path("/img/logo.png"),
            RepositoryContentType::Image
        );
        assert_eq!(
            RepositoryContentType::from_path("/img/photo.jpg"),
            RepositoryContentType::Image
        );
        assert_eq!(
            RepositoryContentType::from_path("/img/photo.jpeg"),
            RepositoryContentType::Image
        );
        assert_eq!(
            RepositoryContentType::from_path("/img/anim.gif"),
            RepositoryContentType::Image
        );
        assert_eq!(
            RepositoryContentType::from_path("/img/LOGO.PNG"),
            RepositoryContentType::Image
        );
    }

    #[test]
    fn test_content_type_from_path_unknown() {
        assert_eq!(
            RepositoryContentType::from_path("/other/file.txt"),
            RepositoryContentType::Unknown
        );
        assert_eq!(
            RepositoryContentType::from_path("/no_extension"),
            RepositoryContentType::Unknown
        );
        assert_eq!(
            RepositoryContentType::from_path(""),
            RepositoryContentType::Unknown
        );
    }

    // -- RepositoryItem tests --

    #[test]
    fn test_repository_item_creation() {
        let item = RepositoryItem {
            path: "/CM/report.ozr".to_string(),
            content_type: RepositoryContentType::Report,
            content: vec![0x01, 0x02, 0x03],
            size: 3,
            compressed: false,
            metadata: vec![("key".to_string(), "value".to_string())],
        };
        assert_eq!(item.path, "/CM/report.ozr");
        assert_eq!(item.content_type, RepositoryContentType::Report);
        assert_eq!(item.content.len(), 3);
        assert_eq!(item.size, 3);
        assert!(!item.compressed);
        assert_eq!(item.metadata.len(), 1);
    }

    #[test]
    fn test_repository_item_clone() {
        let item = RepositoryItem {
            path: "/CM/data.odi".to_string(),
            content_type: RepositoryContentType::DataInterface,
            content: vec![0xFF],
            size: 1,
            compressed: true,
            metadata: vec![],
        };
        let cloned = item.clone();
        assert_eq!(cloned.path, item.path);
        assert_eq!(cloned.content_type, item.content_type);
        assert_eq!(cloned.content, item.content);
        assert_eq!(cloned.compressed, item.compressed);
    }

    // -- RepositoryRequestOptions tests --

    #[test]
    fn test_request_options_default() {
        let opts = RepositoryRequestOptions::default();
        assert!(!opts.refresh);
        assert!(!opts.compressed);
        assert!(opts.extra_info.is_empty());
    }

    #[test]
    fn test_request_options_custom() {
        let opts = RepositoryRequestOptions {
            refresh: true,
            compressed: true,
            extra_info: "test_info".to_string(),
        };
        assert!(opts.refresh);
        assert!(opts.compressed);
        assert_eq!(opts.extra_info, "test_info");
    }

    #[test]
    fn test_request_options_clone() {
        let opts = RepositoryRequestOptions {
            refresh: true,
            compressed: false,
            extra_info: "metadata".to_string(),
        };
        let cloned = opts.clone();
        assert_eq!(cloned.refresh, opts.refresh);
        assert_eq!(cloned.compressed, opts.compressed);
        assert_eq!(cloned.extra_info, opts.extra_info);
    }

    // -- RepositoryResponse tests --

    #[test]
    fn test_repository_response_default_fields() {
        let resp = RepositoryResponse {
            header: OzMessageHeader {
                magic: 0x2711,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            data: vec![0x01, 0x02],
            status: RepositoryStatus::default(),
            item: None,
        };
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.status, RepositoryStatus::Ready);
        assert!(resp.item.is_none());
    }

    #[test]
    fn test_repository_response_with_item() {
        let item = RepositoryItem {
            path: "/CM/test.ozr".to_string(),
            content_type: RepositoryContentType::Report,
            content: vec![0xDE, 0xAD],
            size: 2,
            compressed: false,
            metadata: vec![],
        };
        let resp = RepositoryResponse {
            header: OzMessageHeader {
                magic: 0x2711,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            data: vec![0xDE, 0xAD],
            status: RepositoryStatus::Complete,
            item: Some(item),
        };
        assert_eq!(resp.status, RepositoryStatus::Complete);
        assert!(resp.item.is_some());
        let item = resp.item.unwrap();
        assert_eq!(item.path, "/CM/test.ozr");
        assert_eq!(item.content_type, RepositoryContentType::Report);
    }

    #[test]
    fn test_repository_response_class_name() {
        assert_eq!(RepositoryResponse::CLASS_NAME, "OZRepositoryResponseItem");
    }
}

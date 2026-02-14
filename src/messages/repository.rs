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
#[cfg(feature = "gzip")]
use crate::gzip;
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
/// - [`size`](Self::size): 응답에서 받은 원본 바이트 크기 (GZIP 압축 해제 전 크기)
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
    /// 응답에서 받은 원본 바이트 크기 (GZIP 압축 해제 전 크기).
    ///
    /// 압축된 응답의 경우 이 값은 압축된 상태의 바이트 수를 나타내며,
    /// `content`의 실제 길이와 동일합니다. 압축 해제 후의 크기는
    /// 별도로 계산해야 합니다.
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
/// ## 데이터 접근
///
/// 파일 데이터는 메모리 중복을 피하기 위해 단일 위치에 저장됩니다:
///
/// - **`item`이 존재할 때**: 파일 바이트는 `item.content`에 저장되며,
///   `data` 필드는 빈 Vec입니다. [`into_data()`](Self::into_data)로 소유권을 이전하세요.
/// - **`item`이 없을 때** (Error 상태 등): 남은 바이트가 `data` 필드에 저장됩니다.
///
/// ## 예시
///
/// ```ignore
/// let response: RepositoryResponse = client.send(&req).await?;
///
/// // 구조화된 접근 (권장)
/// if response.status == RepositoryStatus::Complete {
///     if let Some(item) = &response.item {
///         println!("File: {}, type: {:?}, size: {}", item.path, item.content_type, item.content.len());
///     }
/// }
///
/// // 소유권 이전
/// let bytes: Vec<u8> = response.into_data();
/// ```
#[derive(Debug, Clone)]
pub struct RepositoryResponse {
    /// 응답 메시지 헤더
    pub header: OzMessageHeader,
    /// 남은 raw 바이트 — Error 상태 등 `item`이 없는 경우에만 사용됩니다.
    ///
    /// `item`이 존재할 때 이 필드는 빈 Vec입니다.
    /// 파일 데이터에 접근하려면 `item.content` 또는 [`into_data()`](Self::into_data)를 사용하세요.
    pub data: Vec<u8>,
    /// 파일 상태
    pub status: RepositoryStatus,
    /// 파일 항목 (구조화된 메타데이터 포함)
    pub item: Option<RepositoryItem>,
}

impl RepositoryResponse {
    /// 파일 데이터의 소유권을 이전하여 반환합니다.
    ///
    /// `item`이 존재하면 `item.content`를, 그렇지 않으면 `data` 필드를 반환합니다.
    pub fn into_data(self) -> Vec<u8> {
        if let Some(item) = self.item {
            item.content
        } else {
            self.data
        }
    }

    /// 요청 경로를 기반으로 `RepositoryItem`의 `content_type`과 `path`를 설정합니다.
    ///
    /// `parse_payload` 시점에는 요청 경로 정보가 없으므로, 호출자가 이 메서드로
    /// 후처리할 수 있습니다.
    ///
    /// # 예시
    ///
    /// ```ignore
    /// let resp = RepositoryResponse::parse(&buf)?
    ///     .with_path("/CM/report.ozr");
    /// assert_eq!(resp.item.unwrap().content_type, RepositoryContentType::Report);
    /// ```
    pub fn with_path(mut self, path: &str) -> Self {
        if let Some(ref mut item) = self.item {
            item.path = path.to_string();
            item.content_type = RepositoryContentType::from_path(path);
        }
        self
    }

    #[cfg(feature = "gzip")]
    /// 응답 데이터가 GZIP 압축되어 있으면 해제하여 반환합니다.
    ///
    /// [`RepositoryItem`]의 `compressed` 플래그를 먼저 검사합니다.
    /// `compressed`가 `false`이면 데이터를 그대로 반환합니다.
    /// `compressed`가 `true`이거나 `item`이 없는 경우, 데이터 구조(매직 바이트)를
    /// 검사하여 적절한 해제 방식을 선택합니다:
    /// - GZIP 블록 스트림이면 블록 단위로 해제
    /// - 단일 GZIP 스트림이면 일반 GZIP 해제
    /// - 압축되지 않은 데이터이면 그대로 반환
    ///
    /// # 반환
    ///
    /// 압축 해제된 데이터의 복사본을 반환합니다. 원본은 변경되지 않습니다.
    ///
    /// # 에러
    ///
    /// GZIP 해제에 실패하면 [`OzError::DecompressionError`]를 반환합니다.
    ///
    /// # 예시
    ///
    /// ```ignore
    /// let resp: RepositoryResponse = client.send(&req).await?;
    /// let content = resp.decompressed_content()?;
    /// ```
    pub fn decompressed_content(&self) -> Result<Vec<u8>> {
        let (content, compressed) = if let Some(ref item) = self.item {
            (&item.content, item.compressed)
        } else {
            (&self.data, true) // item이 없으면 매직 바이트 기반 감지에 위임
        };

        // compressed 플래그가 false이면 해제 없이 그대로 반환
        if !compressed {
            return Ok(content.clone());
        }

        gzip::decompress_bytes(content)
    }

    #[cfg(feature = "gzip")]
    /// 응답 데이터가 GZIP 압축되어 있으면 내부에서 해제합니다.
    ///
    /// [`decompressed_content()`](Self::decompressed_content)와 달리, 이 메서드는 `self`를
    /// 변경하여 `item.content`를 압축 해제된 데이터로 교체하고
    /// `item.compressed`를 `false`로 설정합니다.
    ///
    /// `item`이 `None`이면서 `self.data`에 압축 데이터가 있는 경우에도
    /// 해제 처리를 수행하여 `self.data`를 압축 해제된 데이터로 교체합니다.
    ///
    /// # 에러
    ///
    /// GZIP 해제에 실패하면 [`OzError::DecompressionError`]를 반환합니다.
    /// 실패 시 원본 데이터는 변경되지 않습니다.
    ///
    /// # 예시
    ///
    /// ```ignore
    /// let mut resp: RepositoryResponse = client.send(&req).await?;
    /// resp.decompress()?;
    /// // 이제 resp.item.content에 압축 해제된 데이터가 있음
    /// ```
    pub fn decompress(&mut self) -> Result<()> {
        if let Some(ref mut item) = self.item {
            if !item.compressed {
                return Ok(());
            }

            let decompressed = gzip::decompress_bytes(&item.content)?;
            item.content = decompressed;
            item.compressed = false;
        } else if !self.data.is_empty() {
            // item이 없지만 self.data에 압축 데이터가 있는 경우
            let decompressed = gzip::decompress_bytes(&self.data)?;
            self.data = decompressed;
        }
        Ok(())
    }
}

impl OzResponse for RepositoryResponse {
    const CLASS_NAME: &'static str = "OZRepositoryResponseItem";

    fn parse_payload(reader: &mut BufReader, header: OzMessageHeader) -> Result<Self> {
        // 빈 응답: 페이로드가 없으면 기본값으로 반환.
        // OZ 프로토콜 문서에는 빈 페이로드에 대한 명시적 정의가 없으므로,
        // 방어적으로 Ready 상태(기본값)를 반환합니다. 실제 서버에서는
        // Loading 폴링 중 빈 응답이 관찰된 바 있습니다.
        if reader.remaining() == 0 {
            return Ok(Self {
                header,
                data: Vec::new(),
                status: RepositoryStatus::Ready,
                item: None,
            });
        }

        // 상태 코드 최소 4바이트 필요
        if reader.remaining() < 4 {
            return Err(OzError::RepositoryParseError {
                detail: format!(
                    "insufficient bytes for status: need 4, have {}",
                    reader.remaining()
                ),
            });
        }

        // ① RepositoryStatus 파싱 (i32)
        let status_raw = reader.read_i32()?;
        let status = RepositoryStatus::try_from(status_raw)?;

        // ② 나머지 바이트 → 파일 바이너리 데이터
        let remaining = reader.remaining();
        let data = if remaining > 0 {
            reader.read_bytes(remaining)?.to_vec()
        } else {
            Vec::new()
        };

        // Error 상태이면 item 없이 반환 (data에는 남은 바이트 유지)
        if status == RepositoryStatus::Error {
            return Ok(Self {
                header,
                data,
                status,
                item: None,
            });
        }

        // ③ RepositoryItem 구성
        //    data를 item.content로 move하여 메모리 이중 보관을 방지합니다.
        //    RepositoryResponse.data는 빈 Vec이 되며, 파일 데이터는
        //    item.content 또는 into_data()를 통해 접근합니다.
        let (data_field, item) = if !data.is_empty() {
            // GZIP 매직 바이트(0x1f, 0x8b)로 압축 여부 감지
            let compressed = data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b;
            let size = data.len();

            let item = RepositoryItem {
                path: String::new(), // 경로는 요청 컨텍스트에서 with_path()를 통해 설정
                content_type: RepositoryContentType::Unknown,
                content: data, // move — clone 없이 소유권 이전
                size,
                compressed,
                metadata: header.fields.clone(),
            };

            (Vec::new(), Some(item))
        } else {
            (data, None)
        };

        Ok(Self {
            header,
            data: data_field,
            status,
            item,
        })
    }
}

impl OzRequestResponse for RepositoryRequest {
    type Response = RepositoryResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{MAGIC, REQUEST_FRAME_SIZE};
    use crate::messages::common::parse_header;

    /// 테스트 헬퍼: RepositoryRequest를 빌드합니다.
    fn build_repo(path: &str, session_id: &str) -> Vec<u8> {
        RepositoryRequest::new(path).build(session_id).unwrap()
    }

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
        let buf = build_repo("/CM/test.ozr", "12345");
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_repository_request_class_name() {
        let buf = build_repo("/CM/test.ozr", "12345");
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, RepositoryRequest::CLASS_NAME);
    }

    #[test]
    fn test_build_repository_request_payload() {
        let buf = build_repo("/CM/test.ozr", "session123");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.get_field("s"), Some("session123"));

        // Repository payload
        let marker = reader.read_u32().unwrap();
        assert_eq!(marker, RepositoryRequest::TYPE_MARKER.unwrap());
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
        let buf = build_repo("/CM/report.ozr", "sess42");
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

    // -- parse_payload tests --

    /// 테스트용 Repository 응답 바이너리를 생성하는 헬퍼
    ///
    /// 구조: Magic + ClassName(UTF-16BE) + FieldCount + Fields + Status(i32) + FileData
    fn build_test_repo_response(status: i32, file_data: &[u8], fields: &[(&str, &str)]) -> Vec<u8> {
        let mut w = BufWriter::new();
        // 헤더
        w.write_u32(MAGIC).unwrap();
        w.write_utf16be("oz.framework.cp.message.repositoryex.OZRepositoryResponseItem")
            .unwrap();
        w.write_u32(fields.len() as u32).unwrap();
        for (k, v) in fields {
            w.write_utf16be(k).unwrap();
            w.write_utf16be(v).unwrap();
        }
        // 페이로드: status + file data
        w.write_i32(status).unwrap();
        // 파일 데이터를 직접 기록
        for &b in file_data {
            w.write_u8(b).unwrap();
        }
        let pos = w.offset();
        let bytes = w.into_bytes();
        bytes[..pos].to_vec()
    }

    /// 테스트용 에러 응답 바이너리를 생성하는 헬퍼
    fn build_test_exception_response(error_code: i32, message: &str) -> Vec<u8> {
        let mut w = BufWriter::new();
        w.write_u32(MAGIC).unwrap();
        w.write_utf16be("oz.framework.cp.message.OZCPExceptionMessage")
            .unwrap();
        // parse_header가 field_count를 읽으므로 0으로 설정
        w.write_u32(0).unwrap();
        // 에러 코드
        w.write_i32(error_code).unwrap();
        // 메시지 길이 (문자 수)
        let u16_units: Vec<u16> = message.encode_utf16().collect();
        w.write_u32(u16_units.len() as u32).unwrap();
        // 메시지 (UTF-16BE)
        for ch in &u16_units {
            w.write_u16(*ch).unwrap();
        }
        let pos = w.offset();
        let bytes = w.into_bytes();
        bytes[..pos].to_vec()
    }

    #[test]
    fn test_parse_payload_complete_with_data() {
        let file_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let fields = vec![("s", "session123"), ("un", "guest")];
        let buf = build_test_repo_response(2, &file_data, &fields); // status=2 (Complete)

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.status, RepositoryStatus::Complete);
        // data 필드는 빈 Vec (파일 데이터는 item.content에 저장)
        assert!(resp.data.is_empty());
        assert!(resp.item.is_some());

        let item = resp.item.as_ref().unwrap();
        assert_eq!(item.content, file_data);
        assert_eq!(item.size, 6);
        assert!(!item.compressed);
        assert_eq!(item.content_type, RepositoryContentType::Unknown);

        // into_data()로 소유권 이전
        let data = resp.into_data();
        assert_eq!(data, file_data);
    }

    #[test]
    fn test_parse_payload_ready_status() {
        let file_data = vec![0x01, 0x02, 0x03];
        let buf = build_test_repo_response(0, &file_data, &[]); // status=0 (Ready)

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.status, RepositoryStatus::Ready);
        // data 필드는 빈 Vec (파일 데이터는 item.content에 저장)
        assert!(resp.data.is_empty());
        assert!(resp.item.is_some());
        assert_eq!(resp.item.as_ref().unwrap().content, file_data);
    }

    #[test]
    fn test_parse_payload_loading_status() {
        let buf = build_test_repo_response(1, &[], &[]); // status=1 (Loading), no data

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.status, RepositoryStatus::Loading);
        assert!(resp.data.is_empty());
        assert!(resp.item.is_none()); // 데이터가 없으므로 item 없음
    }

    #[test]
    fn test_parse_payload_error_status() {
        let buf = build_test_repo_response(-1, &[0xFF], &[]); // status=-1 (Error)

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.status, RepositoryStatus::Error);
        // Error 상태에서는 item이 None
        assert!(resp.item.is_none());
        // data에는 나머지 바이트가 유지됨
        assert_eq!(resp.data, vec![0xFF]);
    }

    #[test]
    fn test_parse_payload_error_status_no_data() {
        let buf = build_test_repo_response(-1, &[], &[]); // Error with no trailing data

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.status, RepositoryStatus::Error);
        assert!(resp.item.is_none());
        assert!(resp.data.is_empty());
    }

    #[test]
    fn test_parse_payload_empty_response() {
        // 헤더만 있고 페이로드가 전혀 없는 경우
        let mut w = BufWriter::new();
        w.write_u32(MAGIC).unwrap();
        w.write_utf16be("oz.framework.cp.message.repositoryex.OZRepositoryResponseItem")
            .unwrap();
        w.write_u32(0).unwrap(); // 필드 0개
        let pos = w.offset();
        let bytes = w.into_bytes();
        let buf = bytes[..pos].to_vec();

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.status, RepositoryStatus::Ready);
        assert!(resp.data.is_empty());
        assert!(resp.item.is_none());
    }

    #[test]
    fn test_parse_payload_gzip_detection() {
        // GZIP 매직 바이트 (0x1f, 0x8b)로 시작하는 데이터
        let gzip_data = vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00];
        let buf = build_test_repo_response(2, &gzip_data, &[]);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.status, RepositoryStatus::Complete);
        assert!(resp.item.is_some());

        let item = resp.item.as_ref().unwrap();
        assert!(item.compressed);
        assert_eq!(item.content, gzip_data);

        // into_data로도 동일한 데이터 반환
        assert_eq!(resp.into_data(), gzip_data);
    }

    #[test]
    fn test_parse_payload_non_gzip_data() {
        // GZIP 아닌 일반 데이터
        let data = vec![0x50, 0x4B, 0x03, 0x04]; // ZIP 매직, not GZIP
        let buf = build_test_repo_response(2, &data, &[]);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        let item = resp.item.unwrap();
        assert!(!item.compressed);
    }

    #[test]
    fn test_parse_payload_single_byte_not_gzip() {
        // 1바이트 데이터는 GZIP으로 감지되지 않아야 함
        let data = vec![0x1f];
        let buf = build_test_repo_response(2, &data, &[]);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        let item = resp.item.unwrap();
        assert!(!item.compressed);
    }

    #[test]
    fn test_parse_payload_metadata_propagation() {
        let fields = vec![("s", "sess42"), ("un", "admin"), ("cv", "20140527")];
        let data = vec![0xAB, 0xCD];
        let buf = build_test_repo_response(2, &data, &fields);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        let item = resp.item.unwrap();
        // 헤더 필드가 metadata로 전파되어야 함
        assert_eq!(item.metadata.len(), 3);
        assert!(item.metadata.iter().any(|(k, v)| k == "s" && v == "sess42"));
        assert!(item.metadata.iter().any(|(k, v)| k == "un" && v == "admin"));
    }

    #[test]
    fn test_parse_payload_large_file_data() {
        // 큰 파일 데이터 — BufWriter는 9545B 제한이므로 Vec으로 수동 빌드
        let large_data: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();

        let mut buf = Vec::with_capacity(512 + large_data.len());
        // Magic
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        // ClassName (UTF-16BE)
        let class_name = "oz.framework.cp.message.repositoryex.OZRepositoryResponseItem";
        let u16_units: Vec<u16> = class_name.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        // Field count = 0
        buf.extend_from_slice(&0u32.to_be_bytes());
        // Status = 2 (Complete)
        buf.extend_from_slice(&2i32.to_be_bytes());
        // File data
        buf.extend_from_slice(&large_data);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.status, RepositoryStatus::Complete);
        // data 필드는 빈 Vec (파일 데이터는 item.content에 저장)
        assert!(resp.data.is_empty());
        let item = resp.item.as_ref().unwrap();
        assert_eq!(item.content.len(), 10240);
        assert_eq!(item.content, large_data);
    }

    #[test]
    fn test_with_path_sets_content_type_and_path() {
        let file_data = vec![0x01, 0x02];
        let buf = build_test_repo_response(2, &file_data, &[]);

        let resp = RepositoryResponse::parse(&buf)
            .unwrap()
            .with_path("/CM/report.ozr");
        let item = resp.item.as_ref().unwrap();
        assert_eq!(item.path, "/CM/report.ozr");
        assert_eq!(item.content_type, RepositoryContentType::Report);
    }

    #[test]
    fn test_with_path_no_item() {
        // item이 없는 경우 with_path는 아무것도 하지 않음
        let buf = build_test_repo_response(-1, &[], &[]);
        let resp = RepositoryResponse::parse(&buf)
            .unwrap()
            .with_path("/CM/report.ozr");
        assert!(resp.item.is_none());
    }

    #[test]
    fn test_into_data_with_item() {
        let file_data = vec![0xCA, 0xFE];
        let buf = build_test_repo_response(2, &file_data, &[]);
        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.into_data(), file_data);
    }

    #[test]
    fn test_into_data_without_item() {
        // Error 상태: data 필드에 바이트가 있고 item은 None
        let buf = build_test_repo_response(-1, &[0xFF], &[]);
        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.into_data(), vec![0xFF]);
    }

    #[test]
    fn test_parse_payload_unknown_status_code() {
        let buf = build_test_repo_response(99, &[], &[]);

        let err = RepositoryResponse::parse(&buf).unwrap_err();
        assert!(matches!(
            err,
            OzError::UnknownRepositoryStatus { status: 99 }
        ));
    }

    #[test]
    fn test_parse_payload_insufficient_bytes_for_status() {
        // 헤더 후 2바이트만 있는 경우 (status에 4바이트 필요)
        let mut w = BufWriter::new();
        w.write_u32(MAGIC).unwrap();
        w.write_utf16be("oz.framework.cp.message.repositoryex.OZRepositoryResponseItem")
            .unwrap();
        w.write_u32(0).unwrap();
        // status에 필요한 4바이트 중 2바이트만 기록
        w.write_u8(0x00).unwrap();
        w.write_u8(0x02).unwrap();
        let pos = w.offset();
        let bytes = w.into_bytes();
        let buf = bytes[..pos].to_vec();

        let err = RepositoryResponse::parse(&buf).unwrap_err();
        assert!(matches!(err, OzError::RepositoryParseError { .. }));
    }

    #[test]
    fn test_parse_exception_response() {
        let buf = build_test_exception_response(-1, "file not found");

        let err = RepositoryResponse::parse(&buf).unwrap_err();
        assert!(matches!(err, OzError::ProtocolError { code: -1, .. }));
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_parse_exception_response_korean_message() {
        let buf = build_test_exception_response(-999, "파일을 찾을 수 없습니다");

        let err = RepositoryResponse::parse(&buf).unwrap_err();
        assert!(matches!(err, OzError::ProtocolError { code: -999, .. }));
        assert!(err.to_string().contains("파일을 찾을 수 없습니다"));
    }

    #[test]
    fn test_parse_complete_then_access_header() {
        let fields = vec![("s", "my_session")];
        let data = vec![0x01];
        let buf = build_test_repo_response(2, &data, &fields);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.header.get_field("s"), Some("my_session"));
        assert!(resp.header.class_name.contains("OZRepositoryResponseItem"));
    }
}

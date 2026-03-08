//! Repository 요청/응답 메시지
//!
//! OZ 서버에서 .ozr/.odi 파일을 다운로드하는 메시지 타입입니다.
//!
//! # 구조체 개요
//!
//! - [`RepositoryRequest`] — 기본 요청
//! - [`RepositoryRequestOptions`] — 확장 요청 옵션 (리프레시, 압축 등)
//! - [`RepositoryResponse`] — 응답 (헤더 + 구조화된 항목)
//! - [`RepositoryContentType`] — 컨텐츠 타입 (Report, DataInterface, Image, Unknown)
//! - [`RepositoryItem`] — 파일 항목 메타데이터
//!
//! # 예시
//!
//! ```ignore
//! use ozra::messages::repository::{RepositoryRequest, RepositoryRequestOptions};
//! use ozra::messages::traits::OzRequest;
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
/// ## 예시
///
/// ```ignore
/// let response: RepositoryResponse = client.send(&req).await?;
///
/// if let Some(item) = &response.item {
///     println!("File: {}, type: {:?}, size: {}", item.path, item.content_type, item.content.len());
/// }
///
/// // 소유권 이전
/// let bytes: Vec<u8> = response.into_data();
/// ```
#[derive(Debug, Clone)]
pub struct RepositoryResponse {
    /// 응답 메시지 헤더
    pub header: OzMessageHeader,
    /// 파일 항목 (구조화된 메타데이터 포함)
    pub item: Option<RepositoryItem>,
}

impl RepositoryResponse {
    /// 파일 데이터의 소유권을 이전하여 반환합니다.
    pub fn into_data(self) -> Vec<u8> {
        self.item.map(|i| i.content).unwrap_or_default()
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
    /// `compressed`가 `false`이면 데이터를 그대로 반환합니다.
    pub fn decompressed_content(&self) -> Result<Vec<u8>> {
        let Some(ref item) = self.item else {
            return Ok(Vec::new());
        };

        if !item.compressed {
            return Ok(item.content.clone());
        }

        gzip::decompress_bytes(&item.content)
    }

    #[cfg(feature = "gzip")]
    /// 응답 데이터가 GZIP 압축되어 있으면 내부에서 해제합니다.
    ///
    /// `item.content`를 압축 해제된 데이터로 교체하고
    /// `item.compressed`를 `false`로 설정합니다.
    pub fn decompress(&mut self) -> Result<()> {
        if let Some(ref mut item) = self.item {
            if !item.compressed {
                return Ok(());
            }

            let decompressed = gzip::decompress_bytes(&item.content)?;
            item.content = decompressed;
            item.compressed = false;
        }
        Ok(())
    }
}

impl OzResponse for RepositoryResponse {
    const CLASS_NAME: &'static str = "OZRepositoryResponseItem";

    fn parse_payload(reader: &mut BufReader, header: OzMessageHeader) -> Result<Self> {
        if reader.remaining() < 4 {
            return Err(OzError::RepositoryParseError {
                detail: format!(
                    "insufficient bytes for type marker: need 4, have {}",
                    reader.remaining()
                ),
            });
        }

        let type_marker = reader.read_i32()?;
        if type_marker as u32 != RepositoryRequest::TYPE_MARKER.unwrap_or(0) {
            return Err(OzError::RepositoryParseError {
                detail: format!("unexpected type marker: {type_marker:#x}"),
            });
        }

        // bool + i32 + i64 + bool + bool + i32(size) + data + i32(err) + utf16be(msg)
        let _flag = reader.read_bool()?;
        let _reserved = reader.read_i32()?;
        let _timestamp = reader.read_i64()?;
        let compressed = reader.read_bool()?;
        let _flag2 = reader.read_bool()?;

        let size = reader.read_i32()?;
        if size < 0 {
            return Err(OzError::RepositoryParseError {
                detail: format!("negative file size: {size}"),
            });
        }
        let size = size as usize;

        if size > reader.remaining() {
            return Err(OzError::RepositoryParseError {
                detail: format!(
                    "EOF: expected {size} bytes, have {}",
                    reader.remaining()
                ),
            });
        }

        let data = if size > 0 {
            reader.read_bytes(size)?.to_vec()
        } else {
            Vec::new()
        };

        let error_code = reader.read_i32()?;
        let error_message = reader.read_utf16be()?;

        if error_code != 0 {
            return Err(OzError::ProtocolError {
                code: error_code,
                message: error_message,
            });
        }

        let item = if !data.is_empty() {
            Some(RepositoryItem {
                path: String::new(),
                content_type: RepositoryContentType::Unknown,
                content: data,
                size,
                compressed,
                metadata: header.fields.clone(),
            })
        } else {
            None
        };

        Ok(Self { header, item })
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

    fn build_repo(path: &str, session_id: &str) -> Vec<u8> {
        RepositoryRequest::new(path).build(session_id).unwrap()
    }

    /// Type marker(0x100) 형식의 응답 바이너리를 생성하는 헬퍼
    fn build_test_repo_response(
        file_data: &[u8],
        compressed: bool,
        error_code: i32,
        error_message: &str,
        fields: &[(&str, &str)],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256 + file_data.len());
        // 헤더: Magic + ClassName + Fields
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let class_name = "oz.framework.cp.message.repositoryex.OZRepositoryResponseItem";
        let u16_units: Vec<u16> = class_name.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&(fields.len() as u32).to_be_bytes());
        for (k, v) in fields {
            let ku: Vec<u16> = k.encode_utf16().collect();
            buf.extend_from_slice(&(ku.len() as u32).to_be_bytes());
            for u in &ku {
                buf.extend_from_slice(&u.to_be_bytes());
            }
            let vu: Vec<u16> = v.encode_utf16().collect();
            buf.extend_from_slice(&(vu.len() as u32).to_be_bytes());
            for u in &vu {
                buf.extend_from_slice(&u.to_be_bytes());
            }
        }
        // 페이로드: type_marker + bool + i32 + i64 + bool + bool + i32(size) + data + i32(err) + utf16be(msg)
        buf.extend_from_slice(&0x100i32.to_be_bytes());
        buf.push(0); // _flag = false
        buf.extend_from_slice(&0i32.to_be_bytes()); // _reserved
        buf.extend_from_slice(&0i64.to_be_bytes()); // _timestamp
        buf.push(compressed as u8);
        buf.push(0); // _flag2 = false
        buf.extend_from_slice(&(file_data.len() as i32).to_be_bytes());
        buf.extend_from_slice(file_data);
        buf.extend_from_slice(&error_code.to_be_bytes());
        let msg_u16: Vec<u16> = error_message.encode_utf16().collect();
        buf.extend_from_slice(&(msg_u16.len() as i32).to_be_bytes());
        for u in &msg_u16 {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf
    }

    fn build_test_exception_response(error_code: i32, message: &str) -> Vec<u8> {
        let mut w = BufWriter::new();
        w.write_u32(MAGIC).unwrap();
        w.write_utf16be("oz.framework.cp.message.OZCPExceptionMessage")
            .unwrap();
        w.write_u32(0).unwrap();
        w.write_i32(error_code).unwrap();
        let u16_units: Vec<u16> = message.encode_utf16().collect();
        w.write_u32(u16_units.len() as u32).unwrap();
        for ch in &u16_units {
            w.write_u16(*ch).unwrap();
        }
        let pos = w.offset();
        let bytes = w.into_bytes();
        bytes[..pos].to_vec()
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
    }

    #[test]
    fn test_content_type_from_path_unknown() {
        assert_eq!(
            RepositoryContentType::from_path("/other/file.txt"),
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
        assert_eq!(item.content.len(), 3);
        assert!(!item.compressed);
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
    }

    // -- RepositoryResponse tests --

    #[test]
    fn test_repository_response_class_name() {
        assert_eq!(RepositoryResponse::CLASS_NAME, "OZRepositoryResponseItem");
    }

    #[test]
    fn test_parse_payload_with_data() {
        let file_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let fields = vec![("s", "session123"), ("un", "guest")];
        let buf = build_test_repo_response(&file_data, false, 0, "", &fields);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert!(resp.item.is_some());

        let item = resp.item.as_ref().unwrap();
        assert_eq!(item.content, file_data);
        assert_eq!(item.size, 6);
        assert!(!item.compressed);

        let data = resp.into_data();
        assert_eq!(data, file_data);
    }

    #[test]
    fn test_parse_payload_compressed() {
        let file_data = vec![0x1f, 0x8b, 0x08, 0x00];
        let buf = build_test_repo_response(&file_data, true, 0, "", &[]);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        let item = resp.item.as_ref().unwrap();
        assert!(item.compressed);
        assert_eq!(item.content, file_data);
    }

    #[test]
    fn test_parse_payload_not_compressed() {
        let file_data = vec![0x50, 0x4B, 0x03, 0x04];
        let buf = build_test_repo_response(&file_data, false, 0, "", &[]);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        let item = resp.item.unwrap();
        assert!(!item.compressed);
    }

    #[test]
    fn test_parse_payload_empty_data() {
        let buf = build_test_repo_response(&[], false, 0, "", &[]);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert!(resp.item.is_none());
    }

    #[test]
    fn test_parse_payload_error_code() {
        let buf = build_test_repo_response(&[0x01], false, -1, "access denied", &[]);

        let err = RepositoryResponse::parse(&buf).unwrap_err();
        assert!(matches!(err, OzError::ProtocolError { code: -1, .. }));
        assert!(err.to_string().contains("access denied"));
    }

    #[test]
    fn test_parse_payload_error_code_korean() {
        let buf = build_test_repo_response(&[], false, -999, "파일을 찾을 수 없습니다", &[]);

        let err = RepositoryResponse::parse(&buf).unwrap_err();
        assert!(matches!(err, OzError::ProtocolError { code: -999, .. }));
        assert!(err.to_string().contains("파일을 찾을 수 없습니다"));
    }

    #[test]
    fn test_parse_payload_metadata_propagation() {
        let fields = vec![("s", "sess42"), ("un", "admin"), ("cv", "20140527")];
        let buf = build_test_repo_response(&[0xAB, 0xCD], false, 0, "", &fields);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        let item = resp.item.unwrap();
        assert_eq!(item.metadata.len(), 3);
        assert!(item.metadata.iter().any(|(k, v)| k == "s" && v == "sess42"));
        assert!(item.metadata.iter().any(|(k, v)| k == "un" && v == "admin"));
    }

    #[test]
    fn test_parse_payload_insufficient_bytes() {
        let mut w = BufWriter::new();
        w.write_u32(MAGIC).unwrap();
        w.write_utf16be("oz.framework.cp.message.repositoryex.OZRepositoryResponseItem")
            .unwrap();
        w.write_u32(0).unwrap();
        w.write_u8(0x00).unwrap();
        w.write_u8(0x02).unwrap();
        let pos = w.offset();
        let bytes = w.into_bytes();
        let buf = bytes[..pos].to_vec();

        let err = RepositoryResponse::parse(&buf).unwrap_err();
        assert!(matches!(err, OzError::RepositoryParseError { .. }));
    }

    #[test]
    fn test_parse_payload_wrong_type_marker() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let class_name = "oz.framework.cp.message.repositoryex.OZRepositoryResponseItem";
        let u16_units: Vec<u16> = class_name.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes()); // fields = 0
        buf.extend_from_slice(&99i32.to_be_bytes()); // wrong type marker

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
    fn test_with_path_sets_content_type_and_path() {
        let buf = build_test_repo_response(&[0x01, 0x02], false, 0, "", &[]);

        let resp = RepositoryResponse::parse(&buf)
            .unwrap()
            .with_path("/CM/report.ozr");
        let item = resp.item.as_ref().unwrap();
        assert_eq!(item.path, "/CM/report.ozr");
        assert_eq!(item.content_type, RepositoryContentType::Report);
    }

    #[test]
    fn test_with_path_no_item() {
        let buf = build_test_repo_response(&[], false, 0, "", &[]);
        let resp = RepositoryResponse::parse(&buf)
            .unwrap()
            .with_path("/CM/report.ozr");
        assert!(resp.item.is_none());
    }

    #[test]
    fn test_into_data_with_item() {
        let file_data = vec![0xCA, 0xFE];
        let buf = build_test_repo_response(&file_data, false, 0, "", &[]);
        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.into_data(), file_data);
    }

    #[test]
    fn test_into_data_without_item() {
        let buf = build_test_repo_response(&[], false, 0, "", &[]);
        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert!(resp.into_data().is_empty());
    }

    #[test]
    fn test_parse_complete_then_access_header() {
        let fields = vec![("s", "my_session")];
        let buf = build_test_repo_response(&[0x01], false, 0, "", &fields);

        let resp = RepositoryResponse::parse(&buf).unwrap();
        assert_eq!(resp.header.get_field("s"), Some("my_session"));
        assert!(resp.header.class_name.contains("OZRepositoryResponseItem"));
    }
}

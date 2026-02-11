//! # ozra
//!
//! OZReport 바이너리 프로토콜 파서 라이브러리.
//!
//! OZ 프로토콜의 요청/응답 메시지를 인코딩/디코딩하고,
//! DataModule 응답에서 구조화된 데이터를 추출합니다.
//!
//! ## 모듈 구조
//!
//! - [`constants`] — 매직 넘버, 프레임 크기, 마커 상수
//! - [`error`] — 에러 타입 계층 구조 ([`OzError`])
//! - [`types`] — 공유 타입 정의 ([`SqlType`], [`FieldValue`], [`FieldKind`] 등)
//! - [`wire`] — 저수준 바이너리 I/O ([`BufReader`](wire::BufReader), [`BufWriter`](wire::BufWriter))
//! - [`field`] — SQL 타입별 필드 값 디코딩 ([`read_field_value`](field::read_field_value), [`read_row`](field::read_row))
//! - [`codec`] — 프로토콜 코덱 (요청 빌더 + 응답 파서 + DataModule 파싱)
//! - [`client`] — HTTP 클라이언트 (세션 관리 + 통신 플로우) *(feature `"client"` 활성화 시)*
//!
//! ## 사용 예시
//!
//! ```rust
//! use ozra::{SqlType, FieldKind, FieldValue};
//! use ozra::constants::MAGIC;
//!
//! let sql_type = SqlType::try_from(12).unwrap();
//! assert_eq!(sql_type, SqlType::VarChar);
//!
//! let kind = FieldKind::try_from(1).unwrap();
//! assert_eq!(kind, FieldKind::Normal);
//!
//! assert_eq!(MAGIC, 0x2711);
//! ```

#[cfg(feature = "client")]
pub mod client;
pub mod codec;
pub mod constants;
pub mod error;
pub mod field;
pub mod types;
pub mod wire;

// NOTE: Selective re-export — only expose commonly used types
pub use error::{OzError, Result};
pub use types::{
    BasicField, DataModuleMeta, DataModuleResponse, DataSet, DataSetGroup, DataSetInfo, FieldKind,
    FieldValue, OzMessageHeader, RecordInfo, Row, SqlType,
};

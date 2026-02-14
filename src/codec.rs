//! 프로토콜 코덱 모듈 — [`messages`](crate::messages) 모듈로의 호환성 래퍼
//!
//! **이 모듈은 더 이상 직접 구현을 포함하지 않습니다.**
//! 모든 기능이 [`messages`](crate::messages) 모듈로 이전되었으며,
//! 기존 코드와의 호환성을 위해 re-export를 제공합니다.
//!
//! ## 마이그레이션 가이드
//!
//! ```rust,ignore
//! // Before:
//! use ozra::codec::{build_login_request, parse_header, check_error};
//!
//! // After:
//! use ozra::messages::{build_login_request, parse_header, check_error};
//! ```

// Re-export all public items from messages module for backward compatibility
pub use crate::messages::class_names;
pub use crate::messages::common::{check_error, check_error_result, parse_header};
pub use crate::messages::data_module::{
    build_data_module_request, parse_basic_field, parse_data_module, parse_dataset_group,
};
pub use crate::messages::login::build_login_request;
pub use crate::messages::repository::build_repository_request;

// Re-export GZIP blocked compression/decompression
pub use crate::gzip::{decode_gzip_blocked, encode_gzip_blocked, is_gzip_blocked};

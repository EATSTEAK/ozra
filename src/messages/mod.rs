//! OZ 프로토콜 메시지 추상화 모듈
//!
//! 서버-클라이언트 간 전송되는 Request/Response 메시지를 trait 기반으로 추상화합니다.
//!
//! ## 핵심 Trait
//!
//! - [`OzRequest`]: 요청 메시지 직렬화 인터페이스
//! - [`OzResponse`]: 응답 메시지 역직렬화 인터페이스
//! - [`OzRequestResponse`]: 요청-응답 타입 페어링
//!
//! ## 메시지 타입
//!
//! - [`LoginRequest`] / [`LoginResponse`]: 사용자 로그인
//! - [`RepositoryRequest`] / [`RepositoryResponse`]: 리포지토리 파일 다운로드
//! - [`DataModuleRequest`]: DataModule 데이터 조회
//!
//! ## 공통 유틸리티
//!
//! - [`write_common_header`]: 모든 요청에 공통인 헤더 작성
//! - [`parse_header`]: 응답 헤더 파싱
//! - [`parse_exception`]: 에러 응답 파싱
//! - [`check_error`]: 응답에서 에러 감지
//! - [`check_error_result`]: 응답에서 에러 감지 (Result 반환)
//!
//! ## 모듈 구조
//!
//! ```text
//! messages/
//! ├── mod.rs           # 모듈 re-export (현재 파일)
//! ├── traits.rs        # OzRequest, OzResponse, OzRequestResponse trait 정의
//! ├── common.rs        # 공통 헤더 빌더/파서
//! ├── login.rs         # LoginRequest/LoginResponse
//! ├── repository.rs    # RepositoryRequest/RepositoryResponse
//! └── data_module.rs   # DataModuleRequest + DataModuleResponse 파싱
//! ```

pub mod common;
pub mod data_module;
pub mod login;
pub mod repository;
mod traits;
pub mod transaction;

// Trait re-exports
pub use traits::{OzRequest, OzRequestResponse, OzResponse};

// Common utilities re-export
pub use common::{
    check_error, check_error_result, parse_exception, parse_header, write_common_header,
    write_common_header_with_auth,
};

// Message type re-exports
pub use data_module::{
    DataModuleRequest, build_data_module_request, parse_basic_field, parse_data_module,
    parse_dataset_group,
};
pub use login::{LoginRequest, LoginResponse, build_login_request};
pub use repository::{
    RepositoryContentType, RepositoryItem, RepositoryRequest, RepositoryRequestOptions,
    RepositoryResponse, RepositoryStatus, build_repository_request,
};
pub use transaction::{
    TransactionDataSet, TransactionRequest, TransactionResponse, build_transaction_request,
};

/// 메시지 클래스명 상수
///
/// 각 메시지 타입의 associated const와 동일한 값을 제공합니다.
/// 기존 코드와의 호환성을 위해 유지합니다.
pub mod class_names {
    use super::*;

    /// UserLogin 요청 클래스명
    pub const USER_LOGIN: &str = LoginRequest::CLASS_NAME;
    /// Repository 요청 클래스명
    pub const REPOSITORY_ITEM: &str = RepositoryRequest::CLASS_NAME;
    /// DataModule 요청 클래스명
    pub const DATA_MODULE: &str = DataModuleRequest::CLASS_NAME;
    /// Transaction 요청 클래스명
    pub const TRANSACTION: &str = TransactionRequest::CLASS_NAME;
}

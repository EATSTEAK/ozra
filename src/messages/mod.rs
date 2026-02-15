//! OZ 프로토콜 메시지 추상화 모듈
//!
//! 서버-클라이언트 간 전송되는 Request/Response 메시지를 trait 기반으로 추상화합니다.
//!
//! ## 핵심 Trait
//!
//! - [`traits::OzRequest`]: 요청 메시지 직렬화 인터페이스
//! - [`traits::OzResponse`]: 응답 메시지 역직렬화 인터페이스
//! - [`traits::OzRequestResponse`]: 요청-응답 타입 페어링
//!
//! ## 메시지 타입
//!
//! - [`login::LoginRequest`] / [`login::LoginResponse`]: 사용자 로그인
//! - [`repository::RepositoryRequest`] / [`repository::RepositoryResponse`]: 리포지토리 파일 다운로드
//! - [`data_module::DataModuleRequest`]: DataModule 데이터 조회
//!
//! ## 공통 유틸리티
//!
//! - [`common::write_common_header`]: 모든 요청에 공통인 헤더 작성
//! - [`common::parse_header`]: 응답 헤더 파싱
//! - [`common::parse_exception`]: 에러 응답 파싱
//! - [`common::check_error`]: 응답에서 에러 감지
//! - [`common::check_error_result`]: 응답에서 에러 감지 (Result 반환)
//!
//! ## 모듈 구조
//!
//! ```text
//! messages/
//! ├── mod.rs           # 모듈 정의 (현재 파일)
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
pub mod traits;
pub mod transaction;

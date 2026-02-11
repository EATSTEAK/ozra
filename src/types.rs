//! OZ 프로토콜에서 사용하는 공유 타입 정의입니다.
//!
//! [`SqlType`], [`FieldValue`], [`FieldKind`] 등 코덱과 필드 모듈 전반에서
//! 공유되는 타입을 정의합니다.

use crate::error::OzError;

/// OZReport가 사용하는 SQL 타입 코드
///
/// Java JDBC 타입 코드와 동일하며, 각 코드는 DataModule 응답에서
/// 필드 값의 바이너리 인코딩 방식을 결정합니다.
///
/// 필드 클래스 매핑:
/// - **BasicStringField**: [`Char`](Self::Char), [`VarChar`](Self::VarChar), [`LongVarChar`](Self::LongVarChar), [`Clob`](Self::Clob)
/// - **BasicStringField2** (boolean prefix 없음): [`Numeric`](Self::Numeric), [`Decimal`](Self::Decimal)
/// - **BasicSmallField** (4B, sentinel null): [`TinyInt`](Self::TinyInt), [`SmallInt`](Self::SmallInt)
/// - **BasicIntField** (bool + 4B): [`Integer`](Self::Integer)
/// - **BasicLongField** (bool + 8B): [`BigInt`](Self::BigInt)
/// - **BasicFloatField** (bool + 4B): [`Real`](Self::Real)
/// - **BasicDoubleField** (bool + 8B): [`Float`](Self::Float), [`Double`](Self::Double)
/// - **BasicBooleanField** (1B, null 없음): [`Bit`](Self::Bit)
/// - **BasicDateField** (8B, sentinel null): [`Date`](Self::Date), [`Time`](Self::Time), [`Timestamp`](Self::Timestamp)
/// - **BasicBinaryField** (length-prefixed): [`Binary`](Self::Binary), [`VarBinary`](Self::VarBinary), [`LongVarBinary`](Self::LongVarBinary), [`Blob`](Self::Blob)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SqlType {
    // 문자열 계열 (BasicStringField)
    /// CHAR (JDBC 코드 1)
    Char = 1,
    /// VARCHAR (JDBC 코드 12)
    VarChar = 12,
    /// LONGVARCHAR (JDBC 코드 -1)
    LongVarChar = -1,
    /// CLOB (JDBC 코드 2005)
    Clob = 2005,

    // NOTE: Numeric string types (BasicStringField2) — no boolean prefix!
    /// NUMERIC (JDBC 코드 2) — boolean prefix 없음
    Numeric = 2,
    /// DECIMAL (JDBC 코드 3) — boolean prefix 없음
    Decimal = 3,

    // 정수 계열
    /// TINYINT (JDBC 코드 -6) — BasicSmallField (4B, sentinel null)
    TinyInt = -6,
    /// SMALLINT (JDBC 코드 5) — BasicSmallField (4B, sentinel null)
    SmallInt = 5,
    /// INTEGER (JDBC 코드 4) — BasicIntField (bool + 4B)
    Integer = 4,
    /// BIGINT (JDBC 코드 -5) — BasicLongField (bool + 8B)
    BigInt = -5,

    // 부동소수점 계열
    /// REAL (JDBC 코드 7) — BasicFloatField (bool + 4B)
    Real = 7,
    /// FLOAT (JDBC 코드 6) — BasicDoubleField (bool + 8B)
    Float = 6,
    /// DOUBLE (JDBC 코드 8) — BasicDoubleField (bool + 8B)
    Double = 8,

    // 불리언
    /// BIT (JDBC 코드 -7) — BasicBooleanField (1B, null 없음)
    Bit = -7,

    // 날짜/시간 계열 (8B epoch ms, sentinel null)
    /// DATE (JDBC 코드 91)
    Date = 91,
    /// TIME (JDBC 코드 92)
    Time = 92,
    /// TIMESTAMP (JDBC 코드 93)
    Timestamp = 93,

    // 바이너리 계열 (length-prefixed)
    /// BINARY (JDBC 코드 -2)
    Binary = -2,
    /// VARBINARY (JDBC 코드 -3)
    VarBinary = -3,
    /// LONGVARBINARY (JDBC 코드 -4)
    LongVarBinary = -4,
    /// BLOB (JDBC 코드 2004)
    Blob = 2004,
}

impl TryFrom<i32> for SqlType {
    type Error = OzError;

    fn try_from(code: i32) -> Result<Self, Self::Error> {
        match code {
            1 => Ok(SqlType::Char),
            2 => Ok(SqlType::Numeric),
            3 => Ok(SqlType::Decimal),
            4 => Ok(SqlType::Integer),
            5 => Ok(SqlType::SmallInt),
            6 => Ok(SqlType::Float),
            7 => Ok(SqlType::Real),
            8 => Ok(SqlType::Double),
            12 => Ok(SqlType::VarChar),
            91 => Ok(SqlType::Date),
            92 => Ok(SqlType::Time),
            93 => Ok(SqlType::Timestamp),
            -1 => Ok(SqlType::LongVarChar),
            -2 => Ok(SqlType::Binary),
            -3 => Ok(SqlType::VarBinary),
            -4 => Ok(SqlType::LongVarBinary),
            -5 => Ok(SqlType::BigInt),
            -6 => Ok(SqlType::TinyInt),
            -7 => Ok(SqlType::Bit),
            2004 => Ok(SqlType::Blob),
            2005 => Ok(SqlType::Clob),
            _ => Err(OzError::UnknownSqlType { code }),
        }
    }
}

/// IBasicField의 종류
///
/// OZ 프로토콜에서 필드는 Normal(1) 또는 Calculated(2) 중 하나입니다.
/// Calculated 필드는 추가로 `parsingCode` (계산식 문자열)를 가집니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum FieldKind {
    /// 일반 필드 (kind = 1)
    Normal = 1,
    /// 계산 필드 (kind = 2) — 추가 parsingCode 존재
    Calculated = 2,
}

impl TryFrom<i32> for FieldKind {
    type Error = OzError;

    fn try_from(kind: i32) -> Result<Self, Self::Error> {
        match kind {
            1 => Ok(FieldKind::Normal),
            2 => Ok(FieldKind::Calculated),
            _ => Err(OzError::UnknownFieldKind { kind }),
        }
    }
}

/// DataModule 응답에서 파싱된 단일 필드 값
///
/// 각 SQL 타입에 따라 적절한 Rust 네이티브 타입으로 변환됩니다.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// SQL NULL
    Null,
    /// 문자열 (CHAR, VARCHAR, LONGVARCHAR, CLOB, NUMERIC, DECIMAL)
    String(String),
    /// 정수 값 (TINYINT, SMALLINT, INTEGER)
    Int(i32),
    /// 큰 정수 값 (BIGINT)
    Long(i64),
    /// 단정밀도 부동소수점 (REAL)
    Float(f32),
    /// 배정밀도 부동소수점 (FLOAT, DOUBLE)
    Double(f64),
    /// 불리언 (BIT)
    Bool(bool),
    /// 날짜/시간 (DATE, TIME, TIMESTAMP) — epoch milliseconds
    DateTime(i64),
    /// 바이너리 데이터 (BINARY, VARBINARY, LONGVARBINARY, BLOB)
    Binary(Vec<u8>),
}

impl FieldValue {
    /// null 여부 확인
    pub fn is_null(&self) -> bool {
        matches!(self, FieldValue::Null)
    }

    /// 문자열 표현 (POC 호환: 모든 값을 String으로 변환)
    ///
    /// NULL은 빈 문자열, DateTime은 epoch ms 문자열로 변환됩니다.
    pub fn to_string_repr(&self) -> String {
        match self {
            FieldValue::Null => String::new(),
            FieldValue::String(s) => s.clone(),
            FieldValue::Int(v) => v.to_string(),
            FieldValue::Long(v) => v.to_string(),
            FieldValue::Float(v) => v.to_string(),
            FieldValue::Double(v) => v.to_string(),
            FieldValue::Bool(v) => v.to_string(),
            FieldValue::DateTime(ms) => ms.to_string(),
            FieldValue::Binary(b) => format!("[{} bytes]", b.len()),
        }
    }
}

/// OZ 프로토콜 메시지 헤더
///
/// OZ 프로토콜의 **요청과 응답 양쪽에서 사용되는 공통 헤더** 구조입니다.
///
/// ## 와이어 포맷
///
/// ```text
/// Magic(4B) + ClassName(UTF-16BE) + FieldCount(4B) + Fields(UTF-16BE KV pairs)
/// ```
///
/// ## Magic 값
///
/// - 요청/응답 모두 동일한 매직 넘버 `0x00002711` ([`MAGIC`](crate::constants::MAGIC))을 사용합니다.
/// - 매직 넘버가 일치하지 않으면 [`OzError::InvalidMagic`] 에러가 발생합니다.
///
/// ## ClassName 역할
///
/// `class_name` 필드는 프로토콜 동작(operation)을 식별합니다:
/// - **요청 시**: 서버에 보낼 작업을 지정 (예: `OZRepositoryRequestUserLogin`, `FrameworkRequestDataModule`)
/// - **응답 시**: 서버가 처리한 작업의 응답 클래스명을 반환
/// - 에러 응답의 경우 `"ExceptionMessage"`를 포함하는 클래스명이 사용됩니다.
///
/// ## Fields
///
/// 키-값 쌍으로 구성된 헤더 필드입니다. 주요 필드:
/// - `"s"` — 세션 ID ([`session_id()`](Self::session_id)로 접근)
/// - `"un"` / `"p"` — 사용자명 / 비밀번호
/// - `"cv"` — 클라이언트 버전
#[derive(Debug, Clone)]
pub struct OzMessageHeader {
    /// 매직 넘버 (항상 `0x00002711`)
    pub magic: u32,
    /// 메시지 클래스명 — 프로토콜 동작(operation)을 식별
    pub class_name: String,
    /// 헤더 필드 (키-값 쌍, 순서 보존)
    pub fields: Vec<(String, String)>,
}

impl OzMessageHeader {
    /// 필드 값을 키로 검색
    pub fn get_field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// 세션 ID 추출 (필드 "s")
    pub fn session_id(&self) -> Option<&str> {
        self.get_field("s")
    }
}

/// DataModule의 **컬럼 메타데이터** (IBasicField)
///
/// DataModule 응답의 메타데이터 영역에 포함되며, 각 컬럼의 타입과 속성을 기술합니다.
/// 실제 데이터 파싱 시 이 정보를 기반으로 바이너리 디코딩 방식이 결정됩니다.
///
/// ## 데이터 파싱에서의 역할
///
/// - [`sql_type`](Self::sql_type) — 바이너리 인코딩 방식을 결정합니다
///   (예: `VarChar`면 `bool(1B) + UTF(2+NB)`, `Integer`면 `bool(1B) + i32(4B)`)
/// - [`nullable`](Self::nullable) — null 처리 방식을 결정합니다.
///   SQL 타입에 따라 sentinel null (`i32::MIN`), boolean prefix, 또는 빈 문자열 등
///   다양한 null 판별 방식이 사용됩니다.
/// - [`kind`](Self::kind) — `Calculated` 필드는 추가로 `parsing_code`(계산식)를 가집니다.
///
/// 전체 SQL 타입별 인코딩 규칙은 [`field`](crate::field) 모듈 문서를 참조하세요.
#[derive(Debug, Clone)]
pub struct BasicField {
    /// 필드 종류 (Normal 또는 Calculated)
    pub kind: FieldKind,
    /// SQL 타입 — 바이너리 인코딩 방식을 결정
    pub sql_type: SqlType,
    /// 필드명 (컬럼명)
    pub name: String,
    /// null 허용 여부 — null 처리 방식에 영향
    pub nullable: bool,
    /// 계산식 코드 (kind=Calculated일 때만 Some)
    pub parsing_code: Option<String>,
}

/// OZ 프로토콜에서 **하나의 쿼리 결과셋을 묶는 컨테이너** (IDataSetGrp)
///
/// DataModule 응답에는 여러 그룹이 포함될 수 있으며, 각 그룹은 독립적인
/// 컬럼 정의와 데이터셋을 가집니다.
///
/// ## IMetaSet 이중 필드 목록
///
/// OZ 프로토콜의 IMetaSet은 **주 필드 목록**과 **보조 필드 목록** 두 세트로 구성됩니다:
/// - [`fields`](Self::fields) (주 필드) — 실제 데이터 파싱에 사용되는 컬럼 정의
/// - [`secondary_fields`](Self::secondary_fields) (보조 필드) — 파싱 시 반드시 읽어서
///   오프셋을 전진시켜야 하지만, 데이터 디코딩에는 사용되지 않습니다.
///
/// ## datasets 벡터
///
/// 하나의 그룹 내에 여러 데이터셋이 포함될 수 있으며, 각 [`DataSetInfo`]는
/// 해당 데이터셋의 바이트 크기, 행 수, 키 정보를 담고 있습니다.
/// 최종 파싱된 행 데이터는 [`DataModuleResponse::datasets`]에서 그룹명으로 접근합니다.
#[derive(Debug, Clone)]
pub struct DataSetGroup {
    /// 그룹명 (예: `"ET_DEPLAN"`)
    pub name: String,
    /// 타입명 (예: `"ByteArraySet"`)
    pub type_name: String,
    /// 서브타입
    pub subtype: String,
    /// 주 필드 목록 (IMetaSet fieldCount1) — 데이터 파싱에 사용
    pub fields: Vec<BasicField>,
    /// 보조 필드 목록 (IMetaSet fieldCount2) — 오프셋 전진용, 값은 무시
    pub secondary_fields: Vec<BasicField>,
    /// 데이터셋 정보 목록
    pub datasets: Vec<DataSetInfo>,
}

/// 하나의 데이터셋(결과 테이블)의 **크기와 행 수 정보**
///
/// 각 [`DataSetGroup`] 내의 개별 데이터셋에 대한 메타데이터입니다.
/// `byte_size`와 `row_count`는 RecordInfo 배열 파싱 및 데이터 blob에서
/// 행을 디코딩하는 데 사용됩니다.
#[derive(Debug, Clone)]
pub struct DataSetInfo {
    /// 데이터셋의 바이트 크기 (데이터 blob 내 차지하는 총 바이트)
    pub byte_size: i32,
    /// 행 수 — RecordInfo 배열의 엔트리 수와 동일
    pub row_count: i32,
    /// 데이터셋 키 식별자
    pub key: String,
}

/// 각 행(row)이 데이터 blob 내에서 **어디에 위치하는지**를 나타내는 인덱스 엔트리
///
/// RecordInfo 배열은 DataModule 응답의 메타데이터 영역 뒤에 위치하며,
/// 각 엔트리는 데이터 blob 시작점으로부터의 상대 오프셋과 레코드 길이를 담고 있습니다.
/// 파서는 이 정보를 사용하여 데이터 blob 내의 각 행 위치로 점프한 뒤
/// 필드 목록([`BasicField`])에 따라 행 데이터를 디코딩합니다.
#[derive(Debug, Clone, Copy)]
pub struct RecordInfo {
    /// 레코드 길이 (바이트)
    pub length: i32,
    /// 데이터 blob 시작점으로부터의 바이트 오프셋
    pub offset: i32,
}

/// DataModule 응답의 **페이로드 헤더 영역**에서 파싱되는 메타데이터
///
/// 응답 헤더([`OzMessageHeader`]) 직후에 위치하는 페이로드 헤더와 TTk 헤더에서
/// 추출되는 버전 정보 및 크기 정보입니다.
///
/// ## 바이트 레이아웃
///
/// ```text
/// [OzMessageHeader]
/// ├─ payload_size: i32      // 페이로드 헤더 첫 4바이트
/// ├─ unknown1: i32          // (무시)
/// ├─ version_byte: u8       // (무시)
/// ├─ version: i32           // TTk 헤더 시작
/// ├─ prefix: UTF            // "OZBINDEDDATAMODULE" 검증
/// ├─ data_version: i32
/// ├─ unknown2: i32          // (무시)
/// ├─ unknown3: i32          // (무시)
/// └─ group_count: i16       // 이후 그룹 메타데이터 N개
/// ```
#[derive(Debug, Clone)]
pub struct DataModuleMeta {
    /// 페이로드 크기 (페이로드 헤더 첫 4바이트)
    pub payload_size: i32,
    /// TTk 버전 (예: 17)
    pub version: i32,
    /// 데이터 버전 (예: 2040)
    pub data_version: i32,
    /// 그룹 수 — 이후 파싱할 [`DataSetGroup`] 메타데이터 개수
    pub group_count: i16,
    /// 전체 데이터 blob 크기
    pub total_data_size: i32,
}

/// 단일 행: 필드명-값 쌍의 벡터
pub type Row = Vec<(String, FieldValue)>;

/// 데이터셋: 그룹명과 해당 행 목록의 쌍
pub type DataSet = (String, Vec<Row>);

/// 서버로부터 받은 DataModule 응답의 **전체 파싱 결과**
///
/// [`parse_data_module`](crate::codec::parse_data_module)의 반환 타입으로,
/// OZ 프로토콜의 4개 계층을 모두 포함합니다:
///
/// ## 프로토콜 계층
///
/// | 계층 | 필드 | 설명 |
/// |---|---|---|
/// | 1. 메시지 헤더 | [`header`](Self::header) | 매직 넘버, 클래스명, 세션 ID 등 |
/// | 2. 페이로드 메타 | [`meta`](Self::meta) | 버전, 그룹 수, 데이터 크기 등 |
/// | 3. 그룹 메타데이터 | [`groups`](Self::groups) | 컬럼 정의, 데이터셋 정보, 필드 목록 |
/// | 4. 파싱된 데이터 | [`datasets`](Self::datasets) | 실제 행(row) 데이터 |
///
/// ## 데이터 접근
///
/// 사용자는 보통 [`datasets`](Self::datasets)를 통해 데이터에 접근합니다:
/// ```rust,ignore
/// for (group_name, rows) in &response.datasets {
///     for row in rows {
///         for (field_name, value) in row {
///             println!("{}: {}", field_name, value.to_string_repr());
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DataModuleResponse {
    /// 응답 메시지 헤더 (매직, 클래스명, 세션 ID 등)
    pub header: OzMessageHeader,
    /// 페이로드 메타데이터 (버전, 그룹 수, 데이터 크기)
    pub meta: DataModuleMeta,
    /// 데이터셋 그룹 목록 — 컬럼 정의와 데이터셋 정보
    pub groups: Vec<DataSetGroup>,
    /// 파싱된 행 데이터 — `(그룹명, 행 목록)` 쌍의 벡터
    pub datasets: Vec<DataSet>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAGIC;

    // -- SqlType tests --

    #[test]
    fn test_sql_type_try_from_valid_codes() {
        assert_eq!(SqlType::try_from(1).unwrap(), SqlType::Char);
        assert_eq!(SqlType::try_from(2).unwrap(), SqlType::Numeric);
        assert_eq!(SqlType::try_from(3).unwrap(), SqlType::Decimal);
        assert_eq!(SqlType::try_from(4).unwrap(), SqlType::Integer);
        assert_eq!(SqlType::try_from(5).unwrap(), SqlType::SmallInt);
        assert_eq!(SqlType::try_from(6).unwrap(), SqlType::Float);
        assert_eq!(SqlType::try_from(7).unwrap(), SqlType::Real);
        assert_eq!(SqlType::try_from(8).unwrap(), SqlType::Double);
        assert_eq!(SqlType::try_from(12).unwrap(), SqlType::VarChar);
        assert_eq!(SqlType::try_from(91).unwrap(), SqlType::Date);
        assert_eq!(SqlType::try_from(92).unwrap(), SqlType::Time);
        assert_eq!(SqlType::try_from(93).unwrap(), SqlType::Timestamp);
        assert_eq!(SqlType::try_from(-1).unwrap(), SqlType::LongVarChar);
        assert_eq!(SqlType::try_from(-2).unwrap(), SqlType::Binary);
        assert_eq!(SqlType::try_from(-3).unwrap(), SqlType::VarBinary);
        assert_eq!(SqlType::try_from(-4).unwrap(), SqlType::LongVarBinary);
        assert_eq!(SqlType::try_from(-5).unwrap(), SqlType::BigInt);
        assert_eq!(SqlType::try_from(-6).unwrap(), SqlType::TinyInt);
        assert_eq!(SqlType::try_from(-7).unwrap(), SqlType::Bit);
        assert_eq!(SqlType::try_from(2004).unwrap(), SqlType::Blob);
        assert_eq!(SqlType::try_from(2005).unwrap(), SqlType::Clob);
    }

    #[test]
    fn test_sql_type_try_from_invalid_code() {
        let result = SqlType::try_from(9999);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OzError::UnknownSqlType { code: 9999 }
        ));
    }

    #[test]
    fn test_sql_type_repr_values() {
        assert_eq!(SqlType::Char as i32, 1);
        assert_eq!(SqlType::VarChar as i32, 12);
        assert_eq!(SqlType::BigInt as i32, -5);
        assert_eq!(SqlType::Blob as i32, 2004);
    }

    // -- FieldKind tests --

    #[test]
    fn test_field_kind_try_from_valid() {
        assert_eq!(FieldKind::try_from(1).unwrap(), FieldKind::Normal);
        assert_eq!(FieldKind::try_from(2).unwrap(), FieldKind::Calculated);
    }

    #[test]
    fn test_field_kind_try_from_invalid() {
        let result = FieldKind::try_from(3);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OzError::UnknownFieldKind { kind: 3 }
        ));
    }

    #[test]
    fn test_field_kind_repr_values() {
        assert_eq!(FieldKind::Normal as i32, 1);
        assert_eq!(FieldKind::Calculated as i32, 2);
    }

    // -- FieldValue tests --

    #[test]
    fn test_field_value_is_null() {
        assert!(FieldValue::Null.is_null());
        assert!(!FieldValue::Int(42).is_null());
        assert!(!FieldValue::String("hello".to_string()).is_null());
        assert!(!FieldValue::Bool(false).is_null());
    }

    #[test]
    fn test_field_value_variants() {
        let _ = FieldValue::Null;
        let _ = FieldValue::String("test".to_string());
        let _ = FieldValue::Int(42);
        let _ = FieldValue::Long(123456789_i64);
        let _ = FieldValue::Float(1.23_f32);
        let _ = FieldValue::Double(4.56789_f64);
        let _ = FieldValue::Bool(true);
        let _ = FieldValue::DateTime(1700000000000_i64);
        let _ = FieldValue::Binary(vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_field_value_clone_and_eq() {
        let v1 = FieldValue::String("hello".to_string());
        let v2 = v1.clone();
        assert_eq!(v1, v2);

        let v3 = FieldValue::Int(100);
        let v4 = FieldValue::Int(200);
        assert_ne!(v3, v4);
    }

    #[test]
    fn test_field_value_to_string_repr() {
        assert_eq!(FieldValue::Null.to_string_repr(), "");
        assert_eq!(
            FieldValue::String("hello".to_string()).to_string_repr(),
            "hello"
        );
        assert_eq!(FieldValue::Int(42).to_string_repr(), "42");
        assert_eq!(FieldValue::Long(123456789).to_string_repr(), "123456789");
        assert_eq!(FieldValue::Bool(true).to_string_repr(), "true");
        assert_eq!(
            FieldValue::DateTime(1700000000000_i64).to_string_repr(),
            "1700000000000"
        );
        assert_eq!(
            FieldValue::Binary(vec![0x01, 0x02, 0x03]).to_string_repr(),
            "[3 bytes]"
        );
    }

    // -- OzMessageHeader tests --

    #[test]
    fn test_message_header_get_field() {
        let header = OzMessageHeader {
            magic: MAGIC,
            class_name: "TestClass".to_string(),
            fields: vec![
                ("s".to_string(), "session123".to_string()),
                ("un".to_string(), "guest".to_string()),
            ],
        };
        assert_eq!(header.get_field("s"), Some("session123"));
        assert_eq!(header.get_field("un"), Some("guest"));
        assert_eq!(header.get_field("missing"), None);
    }

    #[test]
    fn test_message_header_session_id() {
        let header = OzMessageHeader {
            magic: MAGIC,
            class_name: "TestClass".to_string(),
            fields: vec![("s".to_string(), "-1905".to_string())],
        };
        assert_eq!(header.session_id(), Some("-1905"));
    }

    #[test]
    fn test_message_header_session_id_missing() {
        let header = OzMessageHeader {
            magic: MAGIC,
            class_name: "TestClass".to_string(),
            fields: vec![],
        };
        assert_eq!(header.session_id(), None);
    }

    #[test]
    fn test_message_header_magic_stored() {
        let header = OzMessageHeader {
            magic: MAGIC,
            class_name: "TestClass".to_string(),
            fields: vec![],
        };
        assert_eq!(header.magic, 0x2711);
    }

    // -- BasicField tests --

    #[test]
    fn test_basic_field_normal() {
        let field = BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::VarChar,
            name: "PSUBJ".to_string(),
            nullable: true,
            parsing_code: None,
        };
        assert_eq!(field.kind, FieldKind::Normal);
        assert_eq!(field.sql_type, SqlType::VarChar);
        assert_eq!(field.name, "PSUBJ");
        assert!(field.nullable);
        assert!(field.parsing_code.is_none());
    }

    #[test]
    fn test_basic_field_calculated() {
        let field = BasicField {
            kind: FieldKind::Calculated,
            sql_type: SqlType::Integer,
            name: "CALC_FIELD".to_string(),
            nullable: false,
            parsing_code: Some("expr code".to_string()),
        };
        assert_eq!(field.kind, FieldKind::Calculated);
        assert!(field.parsing_code.is_some());
    }

    // -- DataSetGroup tests --

    #[test]
    fn test_dataset_group() {
        let group = DataSetGroup {
            name: "ET_DEPLAN".to_string(),
            type_name: "ByteArraySet".to_string(),
            subtype: "".to_string(),
            fields: vec![],
            secondary_fields: vec![],
            datasets: vec![DataSetInfo {
                byte_size: 1024,
                row_count: 10,
                key: "ds1".to_string(),
            }],
        };
        assert_eq!(group.name, "ET_DEPLAN");
        assert_eq!(group.type_name, "ByteArraySet");
        assert!(group.secondary_fields.is_empty());
        assert_eq!(group.datasets.len(), 1);
        assert_eq!(group.datasets[0].row_count, 10);
    }

    // -- RecordInfo tests --

    #[test]
    fn test_record_info() {
        let info = RecordInfo {
            length: 256,
            offset: 1024,
        };
        assert_eq!(info.length, 256);
        assert_eq!(info.offset, 1024);
    }

    // -- DataModuleMeta tests --

    #[test]
    fn test_data_module_meta() {
        let meta = DataModuleMeta {
            payload_size: 380,
            version: 17,
            data_version: 2040,
            group_count: 2,
            total_data_size: 8192,
        };
        assert_eq!(meta.payload_size, 380);
        assert_eq!(meta.version, 17);
        assert_eq!(meta.data_version, 2040);
        assert_eq!(meta.group_count, 2);
        assert_eq!(meta.total_data_size, 8192);
    }

    // -- DataModuleResponse tests --

    #[test]
    fn test_data_module_response_empty() {
        let response = DataModuleResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            meta: DataModuleMeta {
                payload_size: 0,
                version: 0,
                data_version: 0,
                group_count: 0,
                total_data_size: 0,
            },
            groups: vec![],
            datasets: vec![],
        };
        assert!(response.groups.is_empty());
        assert!(response.datasets.is_empty());
    }
}

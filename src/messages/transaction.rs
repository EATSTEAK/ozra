//! Transaction 요청/응답 메시지 (type 1801)
//!
//! OZ 서버에서 트랜잭션(데이터 변경/저장)을 실행하는 메시지 타입입니다.
//! DataModule(type 380)이 데이터 조회(SELECT)에 특화된 반면,
//! Transaction은 데이터 변경(INSERT/UPDATE/DELETE)이나
//! 서버 측 비즈니스 로직 실행을 수행합니다.
//!
//! # 페이로드 구조
//!
//! ```text
//! TYPE_MARKER (0x709 = 1801)
//! z6(transactionName)
//! z6(moduleName)
//! writeInt(paramCount)
//! for each param:
//!   z6(key), z6(value)          // UTF-16BE 인코딩
//! writeInt(datasetCount)
//! for each dataset:
//!   [IByteArrayDataSet]          // 데이터셋 직렬화
//! ```
//!
//! # DataModule과의 차이
//!
//! - Type Marker: `0x709` (1801) vs `0x17C` (380)
//! - 파라미터 인코딩: `z6` (UTF-16BE) vs `writeUTF` (Modified UTF-8)
//! - 후행 상수 없음 (DataModule은 trailing constants 3개)
//! - 데이터셋 직렬화 포함 (DataModule은 일반적으로 비어 있음)
//!
//! # INTEGER/SMALLINT 직렬화 그룹핑
//!
//! 프로토콜 문서 `08_transaction_dataset.md` §5.4 `R_.TlW`에 맞춰
//! `write_field_value()` / `read_field_value()` 그룹핑이 수정되었습니다:
//!
//! | 타입 | 직렬화 형식 |
//! |------|------------|
//! | Integer + TinyInt | `i32` / null=`i32::MIN` (0x80000000) |
//! | SmallInt | `bool` + `i32` |
//!
//! Ref: `plans/codebase-improvement-proposal.md` §4.3
//!
//! # 예시
//!
//! ```
//! use ozra::messages::{TransactionRequest, OzRequest};
//! use ozra::constants::REQUEST_FRAME_SIZE;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 파라미터만 포함하는 단순 트랜잭션
//! let req = TransactionRequest {
//!     transaction_name: "SAVE_DATA".to_string(),
//!     module_name: "MY_MODULE".to_string(),
//!     params: vec![
//!         ("order_id".to_string(), "12345".to_string()),
//!         ("status".to_string(), "CONFIRMED".to_string()),
//!     ],
//!     datasets: vec![],
//! };
//! let buf = req.build("session123")?;
//! assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
//! # Ok(())
//! # }
//! ```

use crate::error::Result;
use crate::field::write_row;
use crate::messages::traits::{OzRequest, OzRequestResponse, OzResponse};
use crate::types::{BasicField, DataModuleResponse, OzMessageHeader, Row};
use crate::wire::{BufReader, BufWriter};

/// 트랜잭션에 포함할 데이터셋
///
/// `IByteArrayDataSet` 형식으로 직렬화되어 트랜잭션 요청에 포함됩니다.
/// 필드 메타데이터와 행 데이터를 모두 포함합니다.
///
/// > ⚠️ **주의**: 데이터셋 봉투(envelope) 구조는 JS 소스에서 확인할 수 없으며,
/// > `parse_basic_field()` / `write_row()`의 대칭 구조를 기반으로 구현되었습니다.
/// > 실제 서버 트래픽 캡처를 통한 검증이 필요합니다.
#[derive(Debug, Clone)]
pub struct TransactionDataSet {
    /// 데이터셋 이름
    pub name: String,
    /// 필드 메타데이터
    pub fields: Vec<BasicField>,
    /// 행 데이터 (각 행은 `(필드명, 필드값)` 쌍의 벡터)
    pub rows: Vec<Row>,
}

/// Transaction 요청
///
/// OZ 서버에서 트랜잭션(데이터 변경/저장)을 실행하는 요청입니다.
///
/// # 페이로드 구조
///
/// ```text
/// TYPE_MARKER (0x709 = 1801)
/// z6(transactionName)    — UTF-16BE
/// z6(moduleName)         — UTF-16BE
/// writeInt(paramCount)
/// for each param:
///   z6(key), z6(value)   — UTF-16BE
/// writeInt(datasetCount)
/// for each dataset:
///   [IByteArrayDataSet]
/// ```
///
/// > 📌 DataModule과 달리 후행 상수(trailing constants)가 없으며,
/// > 파라미터는 `writeUTF`가 아닌 `z6`(UTF-16BE)로 인코딩됩니다.
#[derive(Debug, Clone)]
pub struct TransactionRequest {
    /// 트랜잭션 이름 (JS: `oMk.D66`)
    pub transaction_name: String,
    /// 모듈 이름 (JS: `oMk.p8W`)
    pub module_name: String,
    /// 파라미터 키-값 쌍 (JS: `oMk.AKk`)
    pub params: Vec<(String, String)>,
    /// 전송할 데이터셋 (JS: `oMk.RXW` + 루프)
    pub datasets: Vec<TransactionDataSet>,
}

impl OzRequest for TransactionRequest {
    const CLASS_NAME: &'static str = "oz.framework.cp.message.FrameworkRequestTransaction";
    const TYPE_MARKER: Option<u32> = Some(0x709); // 1801

    fn write_payload(&self, writer: &mut BufWriter) -> Result<()> {
        // ① 트랜잭션 이름 (z6 = UTF-16BE)
        writer.write_utf16be(&self.transaction_name)?;

        // ② 모듈 이름 (z6 = UTF-16BE)
        writer.write_utf16be(&self.module_name)?;

        // ③ 파라미터 수 + 키-값 쌍 (z6 인코딩)
        // NOTE: Java writeInt()는 signed 32-bit → write_i32가 의미적으로 정확.
        //       빅엔디안 바이트 레이아웃은 u32/i32 동일하므로 프로토콜 호환성에 영향 없음.
        //       write_dataset() 내부의 fieldCount, rowCount와 일관성 확보.
        writer.write_i32(self.params.len() as i32)?;
        for (key, value) in &self.params {
            writer.write_utf16be(key)?;
            writer.write_utf16be(value)?;
        }

        // ④ 데이터셋 수 + 직렬화
        writer.write_i32(self.datasets.len() as i32)?;
        for dataset in &self.datasets {
            write_dataset(writer, dataset)?;
        }

        Ok(())
    }
}

/// Transaction 응답
///
/// 트랜잭션 실행 결과를 담는 응답 구조체입니다.
///
/// > ⚠️ **주의**: JS 뷰어에는 트랜잭션 응답 파싱 코드가 없으므로,
/// > 성공 응답의 페이로드 구조가 확인되지 않았습니다.
/// > 현재 구현은 헤더만 파싱하고 나머지는 raw 바이트로 저장합니다.
/// > 에러 응답은 기존 `OZCPExceptionMessage` 패턴으로 자동 감지됩니다.
#[derive(Debug, Clone)]
pub struct TransactionResponse {
    /// 응답 헤더 (매직 넘버, 클래스명, 필드 등)
    pub header: OzMessageHeader,
    /// 파싱되지 않은 나머지 페이로드 (응답 구조 미확인)
    pub raw_payload: Vec<u8>,
}

impl OzResponse for TransactionResponse {
    // NOTE: `contains()` 기반 매칭이므로 "Transaction" 문자열을 포함하는
    // 모든 클래스명(요청 클래스명 포함)에 매칭될 수 있음.
    // 예: "FrameworkRequestTransaction"에도 매칭됨.
    // TODO: 서버 응답의 실제 클래스명이 확인되면 더 구체적인 패턴으로 교체할 것.
    const CLASS_NAME: &'static str = "Transaction";

    fn parse_payload(reader: &mut BufReader, header: OzMessageHeader) -> Result<Self> {
        // NOTE: 응답 페이로드 구조가 확인되지 않았으므로 나머지를 raw 바이트로 저장
        let remaining = reader.remaining();
        let raw_payload = if remaining > 0 {
            reader.read_bytes(remaining)?.to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            header,
            raw_payload,
        })
    }
}

impl TransactionResponse {
    /// raw_payload에 대한 읽기 전용 접근을 제공합니다.
    ///
    /// 서버 응답의 페이로드 구조가 확인되지 않은 경우, 이 메서드를 통해
    /// raw 바이트에 접근하여 수동으로 분석할 수 있습니다.
    ///
    /// # 예시
    ///
    /// ```ignore
    /// let response: TransactionResponse = client.send(&req).await?;
    /// let payload = response.raw_payload();
    /// println!("payload length: {}", payload.len());
    /// ```
    pub fn raw_payload(&self) -> &[u8] {
        &self.raw_payload
    }

    /// raw_payload를 DataModule 형식으로 파싱을 시도합니다.
    ///
    /// Transaction 응답이 DataModule과 유사한 형식인 경우에만 성공합니다.
    /// 내부적으로 raw_payload 앞에 원본 헤더를 재구성하여
    /// [`DataModuleResponse::parse()`]에 전달합니다.
    ///
    /// > ⚠️ **주의**: Transaction 응답이 실제로 DataModule 형식을 사용하는지는
    /// > 서버 구현에 따라 다릅니다. 파싱에 실패하면 에러를 반환합니다.
    ///
    /// # 예시
    ///
    /// ```ignore
    /// let response: TransactionResponse = client.send(&req).await?;
    /// match response.try_parse_as_data_module() {
    ///     Ok(dm) => {
    ///         for (group_name, rows) in &dm.datasets {
    ///             println!("{}: {} rows", group_name, rows.len());
    ///         }
    ///     }
    ///     Err(_) => {
    ///         // DataModule 형식이 아닌 경우 raw_payload 사용
    ///         let raw = response.raw_payload();
    ///     }
    /// }
    /// ```
    pub fn try_parse_as_data_module(&self) -> Result<DataModuleResponse> {
        use crate::constants::MAGIC;
        use crate::messages::data_module::parse_data_module;

        // raw_payload만으로는 DataModuleResponse::parse()에 전달할 수 없음.
        // 헤더를 재구성하여 완전한 바이너리를 만듦.
        let mut buf = Vec::with_capacity(128 + self.raw_payload.len());

        // Magic
        buf.extend_from_slice(&MAGIC.to_be_bytes());

        // Class name (UTF-16BE: u32 char_count + UTF-16BE chars)
        let u16_units: Vec<u16> = self.header.class_name.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }

        // Field count + fields
        buf.extend_from_slice(&(self.header.fields.len() as u32).to_be_bytes());
        for (key, value) in &self.header.fields {
            let k_units: Vec<u16> = key.encode_utf16().collect();
            buf.extend_from_slice(&(k_units.len() as u32).to_be_bytes());
            for u in &k_units {
                buf.extend_from_slice(&u.to_be_bytes());
            }
            let v_units: Vec<u16> = value.encode_utf16().collect();
            buf.extend_from_slice(&(v_units.len() as u32).to_be_bytes());
            for u in &v_units {
                buf.extend_from_slice(&u.to_be_bytes());
            }
        }

        // raw_payload (DataModule 페이로드)
        buf.extend_from_slice(&self.raw_payload);

        parse_data_module(&buf)
    }

    /// 응답이 비어 있는지 확인합니다.
    ///
    /// raw_payload가 비어 있으면 `true`를 반환합니다.
    pub fn is_empty(&self) -> bool {
        self.raw_payload.is_empty()
    }

    /// raw_payload의 길이를 반환합니다.
    pub fn payload_len(&self) -> usize {
        self.raw_payload.len()
    }
}

impl OzRequestResponse for TransactionRequest {
    type Response = TransactionResponse;
}

/// 데이터셋을 직렬화합니다.
///
/// > ⚠️ **주의**: JS 소스의 트랜잭션 데이터셋 루프 바디가 비어 있어
/// > 봉투(envelope) 구조가 확인되지 않았습니다.
/// > `parse_basic_field()` / `write_row()`의 대칭 구조를 기반으로 구현되었으며,
/// > 실제 서버 트래픽 캡처를 통한 검증이 필요합니다.
///
/// 직렬화 형식:
/// ```text
/// z6(datasetName)           — UTF-16BE
/// writeInt(fieldCount)
/// for each field:
///   writeInt(kind)           — 1=Normal, 2=Calculated
///   writeInt(sqlType)
///   writeUTF(name)
///   writeBool(nullable)
///   if kind == 2: writeUTF(parsingCode)
/// writeInt(rowCount)
/// for each row:
///   [write_field_value() per field]
/// ```
fn write_dataset(writer: &mut BufWriter, dataset: &TransactionDataSet) -> Result<()> {
    // 데이터셋 이름 (z6 = UTF-16BE)
    writer.write_utf16be(&dataset.name)?;

    // 필드 메타데이터
    writer.write_i32(dataset.fields.len() as i32)?;
    for field in &dataset.fields {
        write_basic_field(writer, field)?;
    }

    // 행 데이터
    writer.write_i32(dataset.rows.len() as i32)?;
    for row in &dataset.rows {
        write_row(writer, &dataset.fields, row)?;
    }

    Ok(())
}

/// [`BasicField`] 메타데이터를 직렬화합니다.
///
/// [`parse_basic_field()`](crate::messages::data_module::parse_basic_field)의 역함수입니다.
///
/// 형식:
/// ```text
/// writeInt(kind)       — 1=Normal, 2=Calculated
/// writeInt(sqlType)
/// writeUTF(name)
/// writeBool(nullable)
/// if kind == 2: writeUTF(parsingCode)
/// ```
fn write_basic_field(writer: &mut BufWriter, field: &BasicField) -> Result<()> {
    writer.write_i32(field.kind as i32)?;
    writer.write_i32(field.sql_type as i32)?;
    writer.write_utf(&field.name)?;
    writer.write_bool(field.nullable)?;

    if field.kind == crate::types::FieldKind::Calculated {
        writer.write_utf(field.parsing_code.as_deref().unwrap_or(""))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{MAGIC, REQUEST_FRAME_SIZE};
    use crate::messages::common::parse_header;
    use crate::types::{FieldKind, FieldValue, SqlType};

    /// 테스트 헬퍼: TransactionRequest를 빌드합니다.
    fn build_tx(
        transaction_name: &str,
        module_name: &str,
        params: &[(String, String)],
        session_id: &str,
    ) -> Vec<u8> {
        let req = TransactionRequest {
            transaction_name: transaction_name.to_string(),
            module_name: module_name.to_string(),
            params: params.to_vec(),
            datasets: vec![],
        };
        req.build(session_id).unwrap()
    }

    // ── 기본 구조체/Trait 테스트 ──────────────────────────────────────

    #[test]
    fn test_transaction_request_class_name() {
        assert_eq!(
            TransactionRequest::CLASS_NAME,
            "oz.framework.cp.message.FrameworkRequestTransaction"
        );
    }

    #[test]
    fn test_transaction_request_type_marker() {
        assert_eq!(TransactionRequest::TYPE_MARKER, Some(0x709));
    }

    #[test]
    fn test_transaction_request_no_trailing_marker() {
        assert_eq!(TransactionRequest::TRAILING_MARKER, None);
    }

    #[test]
    fn test_transaction_response_class_name() {
        assert_eq!(TransactionResponse::CLASS_NAME, "Transaction");
    }

    #[test]
    fn test_transaction_response_exception_pattern() {
        assert_eq!(TransactionResponse::EXCEPTION_PATTERN, "ExceptionMessage");
    }

    // ── 요청 빌드 테스트 ─────────────────────────────────────────────

    #[test]
    fn test_build_transaction_request_size() {
        let params = vec![("arg1".to_string(), "hello".to_string())];
        let buf = build_tx("SAVE_DATA", "MY_MODULE", &params, "12345");
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_transaction_request_magic() {
        let buf = build_tx("TX", "MOD", &[], "sess1");
        let mut reader = BufReader::new(&buf);
        let magic = reader.read_u32().unwrap();
        assert_eq!(magic, MAGIC);
    }

    #[test]
    fn test_build_transaction_request_class_name() {
        let buf = build_tx("TX", "MOD", &[], "sess1");
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, TransactionRequest::CLASS_NAME);
    }

    #[test]
    fn test_build_transaction_request_payload() {
        let params = vec![
            ("arg1".to_string(), "hello".to_string()),
            ("arg2".to_string(), "world".to_string()),
        ];
        let buf = build_tx("SAVE_DATA", "MY_MODULE", &params, "sess1");
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();

        // Type marker
        let type_marker = reader.read_u32().unwrap();
        assert_eq!(type_marker, 0x709);

        // Transaction name (z6 = UTF-16BE)
        let transaction_name = reader.read_utf16be().unwrap();
        assert_eq!(transaction_name, "SAVE_DATA");

        // Module name (z6 = UTF-16BE)
        let module_name = reader.read_utf16be().unwrap();
        assert_eq!(module_name, "MY_MODULE");

        // Param count (write_i32로 기록됨)
        let param_count = reader.read_i32().unwrap();
        assert_eq!(param_count, 2);

        // Param 1
        let k1 = reader.read_utf16be().unwrap();
        let v1 = reader.read_utf16be().unwrap();
        assert_eq!(k1, "arg1");
        assert_eq!(v1, "hello");

        // Param 2
        let k2 = reader.read_utf16be().unwrap();
        let v2 = reader.read_utf16be().unwrap();
        assert_eq!(k2, "arg2");
        assert_eq!(v2, "world");

        // Dataset count (write_i32로 기록됨)
        let dataset_count = reader.read_i32().unwrap();
        assert_eq!(dataset_count, 0);
    }

    #[test]
    fn test_build_transaction_request_no_params() {
        let buf = build_tx("TX", "MOD", &[], "sess1");
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();

        let _type_marker = reader.read_u32().unwrap();
        let _tx_name = reader.read_utf16be().unwrap();
        let _mod_name = reader.read_utf16be().unwrap();
        let param_count = reader.read_i32().unwrap();
        assert_eq!(param_count, 0);
        let dataset_count = reader.read_i32().unwrap();
        assert_eq!(dataset_count, 0);
    }

    #[test]
    fn test_build_transaction_request_korean_names() {
        let params = vec![("키".to_string(), "값".to_string())];
        let buf = build_tx("저장_트랜잭션", "모듈명", &params, "sess1");
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();

        let _type_marker = reader.read_u32().unwrap();
        let tx_name = reader.read_utf16be().unwrap();
        assert_eq!(tx_name, "저장_트랜잭션");
        let mod_name = reader.read_utf16be().unwrap();
        assert_eq!(mod_name, "모듈명");

        let param_count = reader.read_i32().unwrap();
        assert_eq!(param_count, 1);
        let k = reader.read_utf16be().unwrap();
        let v = reader.read_utf16be().unwrap();
        assert_eq!(k, "키");
        assert_eq!(v, "값");
    }

    #[test]
    fn test_all_transaction_requests_exactly_9545_bytes() {
        let params = vec![("a".to_string(), "b".to_string())];
        let buf = build_tx("TX", "MOD", &params, "12345");
        assert_eq!(buf.len(), 9545);
    }

    // ── 라운드트립 테스트 ────────────────────────────────────────────

    #[test]
    fn test_roundtrip_transaction_request() {
        let params = vec![
            ("order_id".to_string(), "12345".to_string()),
            ("status".to_string(), "CONFIRMED".to_string()),
        ];
        let buf = build_tx("SAVE_ORDER", "ORDER_MOD", &params, "sess99");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.class_name, TransactionRequest::CLASS_NAME);
        assert_eq!(header.get_field("s"), Some("sess99"));
    }

    // ── 데이터셋 직렬화 테스트 ───────────────────────────────────────

    #[test]
    fn test_build_transaction_with_dataset() {
        let fields = vec![
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::VarChar,
                name: "NAME".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "AGE".to_string(),
                nullable: true,
                parsing_code: None,
            },
        ];

        let rows = vec![
            vec![
                ("NAME".to_string(), FieldValue::String("Alice".to_string())),
                ("AGE".to_string(), FieldValue::Int(30)),
            ],
            vec![
                ("NAME".to_string(), FieldValue::String("Bob".to_string())),
                ("AGE".to_string(), FieldValue::Int(25)),
            ],
        ];

        let req = TransactionRequest {
            transaction_name: "INSERT_USERS".to_string(),
            module_name: "USER_MOD".to_string(),
            params: vec![("table".to_string(), "USERS".to_string())],
            datasets: vec![TransactionDataSet {
                name: "DS_USERS".to_string(),
                fields,
                rows,
            }],
        };

        let buf = req.build("sess1").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

        // 페이로드 파싱 검증
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();

        let type_marker = reader.read_u32().unwrap();
        assert_eq!(type_marker, 0x709);

        let tx_name = reader.read_utf16be().unwrap();
        assert_eq!(tx_name, "INSERT_USERS");
        let mod_name = reader.read_utf16be().unwrap();
        assert_eq!(mod_name, "USER_MOD");

        let param_count = reader.read_i32().unwrap();
        assert_eq!(param_count, 1);
        let k = reader.read_utf16be().unwrap();
        let v = reader.read_utf16be().unwrap();
        assert_eq!(k, "table");
        assert_eq!(v, "USERS");

        let dataset_count = reader.read_i32().unwrap();
        assert_eq!(dataset_count, 1);

        // 데이터셋 봉투
        let ds_name = reader.read_utf16be().unwrap();
        assert_eq!(ds_name, "DS_USERS");

        let field_count = reader.read_i32().unwrap();
        assert_eq!(field_count, 2);

        // 필드 메타데이터 1: NAME (VarChar)
        let kind1 = reader.read_i32().unwrap();
        assert_eq!(kind1, 1); // Normal
        let sql1 = reader.read_i32().unwrap();
        assert_eq!(sql1, 12); // VarChar
        let fname1 = reader.read_utf().unwrap();
        assert_eq!(fname1, "NAME");
        let nullable1 = reader.read_bool().unwrap();
        assert!(nullable1);

        // 필드 메타데이터 2: AGE (Integer)
        let kind2 = reader.read_i32().unwrap();
        assert_eq!(kind2, 1); // Normal
        let sql2 = reader.read_i32().unwrap();
        assert_eq!(sql2, 4); // Integer
        let fname2 = reader.read_utf().unwrap();
        assert_eq!(fname2, "AGE");
        let nullable2 = reader.read_bool().unwrap();
        assert!(nullable2);

        // 행 수
        let row_count = reader.read_i32().unwrap();
        assert_eq!(row_count, 2);

        // 행 1: "Alice", 30
        // VarChar: bool(false) + writeUTF("Alice")
        let is_null = reader.read_bool().unwrap();
        assert!(!is_null);
        let name_val = reader.read_utf().unwrap();
        assert_eq!(name_val, "Alice");
        // Integer: sentinel i32(30), no bool prefix
        let age_val = reader.read_i32().unwrap();
        assert_eq!(age_val, 30);

        // 행 2: "Bob", 25
        let is_null = reader.read_bool().unwrap();
        assert!(!is_null);
        let name_val = reader.read_utf().unwrap();
        assert_eq!(name_val, "Bob");
        // Integer: sentinel i32(25), no bool prefix
        let age_val = reader.read_i32().unwrap();
        assert_eq!(age_val, 25);
    }

    #[test]
    fn test_build_transaction_empty_dataset() {
        let req = TransactionRequest {
            transaction_name: "TX".to_string(),
            module_name: "MOD".to_string(),
            params: vec![],
            datasets: vec![TransactionDataSet {
                name: "EMPTY".to_string(),
                fields: vec![],
                rows: vec![],
            }],
        };

        let buf = req.build("sess1").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();
        let _type_marker = reader.read_u32().unwrap();
        let _tx_name = reader.read_utf16be().unwrap();
        let _mod_name = reader.read_utf16be().unwrap();
        let _param_count = reader.read_i32().unwrap();
        let dataset_count = reader.read_i32().unwrap();
        assert_eq!(dataset_count, 1);

        let ds_name = reader.read_utf16be().unwrap();
        assert_eq!(ds_name, "EMPTY");
        let field_count = reader.read_i32().unwrap();
        assert_eq!(field_count, 0);
        let row_count = reader.read_i32().unwrap();
        assert_eq!(row_count, 0);
    }

    #[test]
    fn test_build_transaction_multiple_datasets() {
        let req = TransactionRequest {
            transaction_name: "BULK".to_string(),
            module_name: "MOD".to_string(),
            params: vec![],
            datasets: vec![
                TransactionDataSet {
                    name: "DS1".to_string(),
                    fields: vec![BasicField {
                        kind: FieldKind::Normal,
                        sql_type: SqlType::Integer,
                        name: "ID".to_string(),
                        nullable: false,
                        parsing_code: None,
                    }],
                    rows: vec![vec![("ID".to_string(), FieldValue::Int(1))]],
                },
                TransactionDataSet {
                    name: "DS2".to_string(),
                    fields: vec![BasicField {
                        kind: FieldKind::Normal,
                        sql_type: SqlType::VarChar,
                        name: "VAL".to_string(),
                        nullable: true,
                        parsing_code: None,
                    }],
                    rows: vec![vec![(
                        "VAL".to_string(),
                        FieldValue::String("test".to_string()),
                    )]],
                },
            ],
        };

        let buf = req.build("sess1").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();
        let _type_marker = reader.read_u32().unwrap();
        let _tx_name = reader.read_utf16be().unwrap();
        let _mod_name = reader.read_utf16be().unwrap();
        let _param_count = reader.read_i32().unwrap();

        let dataset_count = reader.read_i32().unwrap();
        assert_eq!(dataset_count, 2);

        // DS1
        let ds1_name = reader.read_utf16be().unwrap();
        assert_eq!(ds1_name, "DS1");
        let field_count1 = reader.read_i32().unwrap();
        assert_eq!(field_count1, 1);
        let _kind = reader.read_i32().unwrap();
        let _sql = reader.read_i32().unwrap();
        let _name = reader.read_utf().unwrap();
        let _nullable = reader.read_bool().unwrap();
        let row_count1 = reader.read_i32().unwrap();
        assert_eq!(row_count1, 1);
        // Integer: sentinel i32(1), no bool prefix
        let id_val = reader.read_i32().unwrap();
        assert_eq!(id_val, 1);

        // DS2
        let ds2_name = reader.read_utf16be().unwrap();
        assert_eq!(ds2_name, "DS2");
        let field_count2 = reader.read_i32().unwrap();
        assert_eq!(field_count2, 1);
        let _kind = reader.read_i32().unwrap();
        let _sql = reader.read_i32().unwrap();
        let _name = reader.read_utf().unwrap();
        let _nullable = reader.read_bool().unwrap();
        let row_count2 = reader.read_i32().unwrap();
        assert_eq!(row_count2, 1);
        // VarChar: bool(false) + writeUTF("test")
        let is_null = reader.read_bool().unwrap();
        assert!(!is_null);
        let val = reader.read_utf().unwrap();
        assert_eq!(val, "test");
    }

    #[test]
    fn test_write_basic_field_normal() {
        let mut writer = BufWriter::new();
        let field = BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::VarChar,
            name: "NAME".to_string(),
            nullable: true,
            parsing_code: None,
        };
        write_basic_field(&mut writer, &field).unwrap();

        let data: Vec<u8> = writer.as_bytes()[..writer.offset()].to_vec();
        let mut reader = BufReader::new(&data);
        let kind = reader.read_i32().unwrap();
        assert_eq!(kind, 1);
        let sql = reader.read_i32().unwrap();
        assert_eq!(sql, 12);
        let name = reader.read_utf().unwrap();
        assert_eq!(name, "NAME");
        let nullable = reader.read_bool().unwrap();
        assert!(nullable);
        assert_eq!(reader.offset(), data.len());
    }

    #[test]
    fn test_write_basic_field_calculated() {
        let mut writer = BufWriter::new();
        let field = BasicField {
            kind: FieldKind::Calculated,
            sql_type: SqlType::Integer,
            name: "CALC".to_string(),
            nullable: false,
            parsing_code: Some("expr_code".to_string()),
        };
        write_basic_field(&mut writer, &field).unwrap();

        let data: Vec<u8> = writer.as_bytes()[..writer.offset()].to_vec();
        let mut reader = BufReader::new(&data);
        let kind = reader.read_i32().unwrap();
        assert_eq!(kind, 2);
        let sql = reader.read_i32().unwrap();
        assert_eq!(sql, 4);
        let name = reader.read_utf().unwrap();
        assert_eq!(name, "CALC");
        let nullable = reader.read_bool().unwrap();
        assert!(!nullable);
        let parsing_code = reader.read_utf().unwrap();
        assert_eq!(parsing_code, "expr_code");
        assert_eq!(reader.offset(), data.len());
    }

    // ── 응답 파싱 테스트 ─────────────────────────────────────────────

    #[test]
    fn test_parse_transaction_response_success() {
        let mut buf = Vec::with_capacity(256);

        // 헤더: Magic + ClassName + Fields
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "TransactionResult";
        let u16_units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        // 1 field: s=12345
        buf.extend_from_slice(&1u32.to_be_bytes());
        for s in ["s", "12345"] {
            let units: Vec<u16> = s.encode_utf16().collect();
            buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
            for u in &units {
                buf.extend_from_slice(&u.to_be_bytes());
            }
        }

        // 임의 페이로드
        buf.extend_from_slice(&[0x01, 0x02, 0x03]);

        let response = TransactionResponse::parse(&buf).unwrap();
        assert_eq!(response.header.magic, MAGIC);
        assert_eq!(response.header.class_name, "TransactionResult");
        assert_eq!(response.header.get_field("s"), Some("12345"));
        assert_eq!(response.raw_payload, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_parse_transaction_response_empty_payload() {
        let mut buf = Vec::with_capacity(256);

        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "TransactionOK";
        let u16_units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes()); // 0 fields

        let response = TransactionResponse::parse(&buf).unwrap();
        assert_eq!(response.header.class_name, "TransactionOK");
        assert!(response.raw_payload.is_empty());
    }

    #[test]
    fn test_parse_transaction_response_error() {
        let mut buf = Vec::with_capacity(512);

        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "oz.framework.cp.message.OZCPExceptionMessage";
        let u16_units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes()); // 0 fields

        // 에러 코드 + 에러 메시지 (UTF-16BE: u32 charCount + UTF-16BE chars)
        buf.extend_from_slice(&500i32.to_be_bytes());
        let err_msg = "Transaction failed";
        let err_u16: Vec<u16> = err_msg.encode_utf16().collect();
        buf.extend_from_slice(&(err_u16.len() as u32).to_be_bytes());
        for u in &err_u16 {
            buf.extend_from_slice(&u.to_be_bytes());
        }

        let err = TransactionResponse::parse(&buf).unwrap_err();
        match err {
            crate::error::OzError::ProtocolError { code, message } => {
                assert_eq!(code, 500);
                assert!(message.contains("Transaction failed"));
            }
            _ => panic!("Expected ProtocolError, got {:?}", err),
        }
    }

    #[test]
    fn test_transaction_response_can_handle() {
        assert!(TransactionResponse::can_handle("SomeTransaction"));
        assert!(TransactionResponse::can_handle("TransactionResult"));
        assert!(!TransactionResponse::can_handle("DataModule"));
    }

    // ── 프로토콜 바이트 레벨 검증 ────────────────────────────────────

    #[test]
    fn test_payload_byte_layout_matches_protocol_doc() {
        // 프로토콜 문서 §3.4의 바이트 예시와 일치하는지 확인
        // "SAVE_DATA", "MY_MODULE", params: [("arg1","hello"),("arg2","world")], datasets: 0
        let params = vec![
            ("arg1".to_string(), "hello".to_string()),
            ("arg2".to_string(), "world".to_string()),
        ];
        let buf = build_tx("SAVE_DATA", "MY_MODULE", &params, "sess1");
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();

        // Type marker 바이트 검증: 0x00000709
        let payload_start = reader.offset();
        let type_marker_bytes = &buf[payload_start..payload_start + 4];
        assert_eq!(type_marker_bytes, &[0x00, 0x00, 0x07, 0x09]);

        // z6 인코딩 검증: transactionName 길이 필드
        let tx_len_offset = payload_start + 4; // type marker 이후
        let tx_len_bytes = &buf[tx_len_offset..tx_len_offset + 4];
        assert_eq!(tx_len_bytes, &[0x00, 0x00, 0x00, 0x09]); // "SAVE_DATA".len() = 9
    }

    #[test]
    fn test_type_marker_value_1801() {
        // 0x709 == 1801 확인
        assert_eq!(0x709u32, 1801u32);
        assert_eq!(TransactionRequest::TYPE_MARKER, Some(1801));
    }

    // ── struct 생성/Debug/Clone 테스트 ────────────────────────────────

    #[test]
    fn test_transaction_request_debug_clone() {
        let req = TransactionRequest {
            transaction_name: "TX".to_string(),
            module_name: "MOD".to_string(),
            params: vec![("k".to_string(), "v".to_string())],
            datasets: vec![],
        };
        let cloned = req.clone();
        assert_eq!(format!("{:?}", req), format!("{:?}", cloned));
    }

    #[test]
    fn test_transaction_dataset_debug_clone() {
        let ds = TransactionDataSet {
            name: "DS".to_string(),
            fields: vec![],
            rows: vec![],
        };
        let cloned = ds.clone();
        assert_eq!(format!("{:?}", ds), format!("{:?}", cloned));
    }

    #[test]
    fn test_transaction_response_debug_clone() {
        let resp = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            raw_payload: vec![1, 2, 3],
        };
        let cloned = resp.clone();
        assert_eq!(resp.header.magic, cloned.header.magic);
        assert_eq!(resp.raw_payload, cloned.raw_payload);
    }

    // ── 데이터셋 Null 값 직렬화 테스트 ───────────────────────────────

    #[test]
    fn test_dataset_with_null_values() {
        let fields = vec![
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::VarChar,
                name: "NAME".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "AGE".to_string(),
                nullable: true,
                parsing_code: None,
            },
        ];

        let rows = vec![vec![
            ("NAME".to_string(), FieldValue::Null),
            ("AGE".to_string(), FieldValue::Null),
        ]];

        let req = TransactionRequest {
            transaction_name: "TX".to_string(),
            module_name: "MOD".to_string(),
            params: vec![],
            datasets: vec![TransactionDataSet {
                name: "DS".to_string(),
                fields,
                rows,
            }],
        };

        let buf = req.build("sess1").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

        // 페이로드에서 데이터셋 부분까지 읽기
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();
        let _type_marker = reader.read_u32().unwrap();
        let _tx_name = reader.read_utf16be().unwrap();
        let _mod_name = reader.read_utf16be().unwrap();
        let _param_count = reader.read_i32().unwrap();
        let _dataset_count = reader.read_i32().unwrap();
        let _ds_name = reader.read_utf16be().unwrap();

        let field_count = reader.read_i32().unwrap();
        assert_eq!(field_count, 2);
        // 필드 메타 스킵
        for _ in 0..2 {
            let _kind = reader.read_i32().unwrap();
            let _sql = reader.read_i32().unwrap();
            let _name = reader.read_utf().unwrap();
            let _nullable = reader.read_bool().unwrap();
        }

        let row_count = reader.read_i32().unwrap();
        assert_eq!(row_count, 1);

        // VarChar null: bool(true)
        let is_null = reader.read_bool().unwrap();
        assert!(is_null);
        // Integer null: sentinel i32::MIN
        let int_null = reader.read_i32().unwrap();
        assert_eq!(int_null, i32::MIN);
    }

    // ── TransactionResponse 편의 메서드 테스트 ──────────────────────────

    #[test]
    fn test_transaction_response_raw_payload_accessor() {
        let resp = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            raw_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert_eq!(resp.raw_payload(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_transaction_response_raw_payload_empty() {
        let resp = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            raw_payload: vec![],
        };
        assert!(resp.raw_payload().is_empty());
    }

    #[test]
    fn test_transaction_response_is_empty() {
        let empty = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            raw_payload: vec![],
        };
        assert!(empty.is_empty());

        let nonempty = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            raw_payload: vec![0x01],
        };
        assert!(!nonempty.is_empty());
    }

    #[test]
    fn test_transaction_response_payload_len() {
        let resp = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "Test".to_string(),
                fields: vec![],
            },
            raw_payload: vec![0x01, 0x02, 0x03],
        };
        assert_eq!(resp.payload_len(), 3);
    }

    #[test]
    fn test_try_parse_as_data_module_invalid_data() {
        // 임의의 바이트는 DataModule 형식이 아니므로 에러 반환
        let resp = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "TransactionResult".to_string(),
                fields: vec![("s".to_string(), "12345".to_string())],
            },
            raw_payload: vec![0x01, 0x02, 0x03, 0x04],
        };
        let result = resp.try_parse_as_data_module();
        assert!(result.is_err());
    }

    #[test]
    fn test_try_parse_as_data_module_empty_payload() {
        // 빈 페이로드로 시도하면 에러 반환
        let resp = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "TransactionResult".to_string(),
                fields: vec![],
            },
            raw_payload: vec![],
        };
        let result = resp.try_parse_as_data_module();
        assert!(result.is_err());
    }

    #[test]
    fn test_try_parse_as_data_module_success() {
        use crate::constants::DATA_MODULE_PREFIX;

        // DataModule 응답의 유효한 페이로드를 raw_payload에 넣어 테스트
        let mut payload = Vec::with_capacity(512);

        // === 페이로드 헤더 ===
        payload.extend_from_slice(&380i32.to_be_bytes()); // payload_size
        payload.extend_from_slice(&0i32.to_be_bytes()); // unknown1
        payload.push(0x01); // version_byte

        // === TTk 헤더 ===
        payload.extend_from_slice(&17i32.to_be_bytes()); // version
        let prefix = DATA_MODULE_PREFIX;
        payload.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        payload.extend_from_slice(prefix.as_bytes());
        payload.extend_from_slice(&2040i32.to_be_bytes()); // data_version
        payload.extend_from_slice(&0i32.to_be_bytes()); // unknown2
        payload.extend_from_slice(&0i32.to_be_bytes()); // unknown3

        // === 그룹 메타데이터 ===
        payload.extend_from_slice(&1i16.to_be_bytes()); // group_count = 1

        // Group: "TxGroup" with 1 VarChar field, 1 row
        let group_name = "TxGroup";
        payload.extend_from_slice(&(group_name.len() as u16).to_be_bytes());
        payload.extend_from_slice(group_name.as_bytes());
        let type_name = "ByteArraySet";
        payload.extend_from_slice(&(type_name.len() as u16).to_be_bytes());
        payload.extend_from_slice(type_name.as_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes()); // subtype = ""

        // 주 필드 1개 (VarChar "RESULT")
        payload.extend_from_slice(&1i32.to_be_bytes()); // field_count1
        payload.extend_from_slice(&1i32.to_be_bytes()); // kind = Normal
        payload.extend_from_slice(&12i32.to_be_bytes()); // sql_type = VarChar
        let fname = "RESULT";
        payload.extend_from_slice(&(fname.len() as u16).to_be_bytes());
        payload.extend_from_slice(fname.as_bytes());
        payload.push(0x01); // nullable

        // 보조 필드 0개
        payload.extend_from_slice(&0i32.to_be_bytes());

        // 데이터셋 1개, 1행
        payload.extend_from_slice(&1i32.to_be_bytes()); // ds_count
        payload.extend_from_slice(&20i32.to_be_bytes()); // byte_size
        payload.extend_from_slice(&1i32.to_be_bytes()); // row_count = 1
        let dk = "ds0";
        payload.extend_from_slice(&(dk.len() as u16).to_be_bytes());
        payload.extend_from_slice(dk.as_bytes());

        // === total_data_size ===
        payload.extend_from_slice(&20i32.to_be_bytes());

        // === RecordInfo (1행) ===
        let row_data = {
            let mut v = Vec::new();
            v.push(0x00); // VarChar not null
            let val = "SUCCESS";
            v.extend_from_slice(&(val.len() as u16).to_be_bytes());
            v.extend_from_slice(val.as_bytes());
            v
        };
        payload.extend_from_slice(&(row_data.len() as i32).to_be_bytes()); // length
        payload.extend_from_slice(&0i32.to_be_bytes()); // offset

        // === 데이터 blob ===
        payload.extend_from_slice(&row_data);

        // TransactionResponse 구성
        let resp = TransactionResponse {
            header: OzMessageHeader {
                magic: MAGIC,
                class_name: "TransactionResult".to_string(),
                fields: vec![("s".to_string(), "sess99".to_string())],
            },
            raw_payload: payload,
        };

        let dm = resp.try_parse_as_data_module().unwrap();
        assert_eq!(dm.header.class_name, "TransactionResult");
        assert_eq!(dm.header.get_field("s"), Some("sess99"));
        assert_eq!(dm.meta.version, 17);
        assert_eq!(dm.groups.len(), 1);
        assert_eq!(dm.groups[0].name, "TxGroup");
        assert_eq!(dm.datasets.len(), 1);
        let (group_name, rows) = &dm.datasets[0];
        assert_eq!(group_name, "TxGroup");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0][0],
            (
                "RESULT".to_string(),
                FieldValue::String("SUCCESS".to_string())
            )
        );
    }
}

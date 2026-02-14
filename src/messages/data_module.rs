//! DataModule 요청/응답 메시지
//!
//! OZ 서버에서 데이터를 조회하는 메시지 타입입니다.
//!
//! # 예시
//!
//! ```ignore
//! use ozra::messages::{DataModuleRequest, OzRequest};
//!
//! let req = DataModuleRequest {
//!     odi_name: "report.odi".to_string(),
//!     category: "/CM".to_string(),
//!     params: vec![("year".to_string(), "2026".to_string())],
//! };
//! let buf = req.build("session123")?;
//! ```

use crate::constants::{DATA_MODULE_PREFIX, SUB_MAGIC};
use crate::error::{OzError, Result};
use crate::field::read_row;
use crate::messages::common::parse_header;
use crate::messages::traits::{OzRequest, OzRequestResponse, OzResponse};
use crate::types::{
    BasicField, DataModuleMeta, DataModuleResponse, DataSet, DataSetGroup, DataSetInfo, FieldKind,
    OzMessageHeader, RecordInfo, SqlType,
};
use crate::wire::{BufReader, BufWriter};

/// DataModule 요청
///
/// OZ 서버에서 DataModule 데이터를 조회하는 요청입니다.
///
/// # 페이로드 구조
///
/// ```text
/// TYPE_MARKER (0x17C)
/// UTF-16BE(odi_name)
/// u32(SUB_MAGIC = 0x2710)
/// UTF-16BE(category)
/// u8(0x00)  // T1E = false
/// u8(0x00)  // w0J = false
/// UTF-16BE("")  // DPk = empty
/// u32(param_count)
/// for each param:
///   UTF-16BE(key)
///   UTF-16BE(value)
/// u32(2)    // trailing const 1
/// u32(0x20) // trailing const 2
/// u32(0x11) // trailing const 3
/// ```
#[derive(Debug, Clone)]
pub struct DataModuleRequest {
    /// ODI 파일명 (예: `"report.odi"`)
    pub odi_name: String,
    /// 카테고리 (예: `"/CM"`)
    pub category: String,
    /// 쿼리 파라미터 (키-값 쌍)
    pub params: Vec<(String, String)>,
}

impl DataModuleRequest {
    /// Trailing constant 1
    pub const TRAILING_CONST_1: u32 = 2;
    /// Trailing constant 2
    pub const TRAILING_CONST_2: u32 = 0x20;
    /// Trailing constant 3
    pub const TRAILING_CONST_3: u32 = 0x11;
}

impl OzRequest for DataModuleRequest {
    const CLASS_NAME: &'static str = "oz.framework.cp.message.FrameworkRequestDataModule";
    const TYPE_MARKER: Option<u32> = Some(0x17C);

    fn write_payload(&self, writer: &mut BufWriter) -> Result<()> {
        writer.write_utf16be(&self.odi_name)?;
        writer.write_u32(SUB_MAGIC)?;
        writer.write_utf16be(&self.category)?;
        writer.write_u8(0x00)?; // T1E = false
        writer.write_u8(0x00)?; // w0J = false
        writer.write_utf16be("")?; // DPk = empty

        writer.write_u32(self.params.len() as u32)?;
        for (key, value) in &self.params {
            writer.write_utf16be(key)?;
            writer.write_utf16be(value)?;
        }

        // Trailing constants
        writer.write_u32(Self::TRAILING_CONST_1)?;
        writer.write_u32(Self::TRAILING_CONST_2)?;
        writer.write_u32(Self::TRAILING_CONST_3)?;

        Ok(())
    }
}

/// CompactDataModule 요청 (서브타입 382, `Kn.C3L`)
///
/// [`DataModuleRequest`](380)의 간결 버전으로, 파라미터·플래그·trailing constants를 생략합니다.
/// 서버 응답 형식은 380과 동일한 [`DataModuleResponse`]입니다.
///
/// # 380 vs 382 차이
///
/// | 필드               | 380 (기본) | 382 (간결) |
/// |--------------------|-----------|-----------|
/// | odi_name           | ✅         | ✅         |
/// | sub_magic (iwc)    | ✅         | ✅         |
/// | category (YKU)     | ✅         | ✅         |
/// | T1E 플래그         | ✅         | ❌         |
/// | w0J 압축 플래그    | ✅         | ✅ (조건부) |
/// | DPk 추가 정보      | ✅ (조건부)| ❌         |
/// | 파라미터 맵        | ✅ (조건부)| ❌         |
/// | trailing constants | ✅         | ❌         |
///
/// # 페이로드 구조
///
/// ```text
/// TYPE_MARKER (0x17E = 382)
/// UTF-16BE(odi_name)
/// u32(SUB_MAGIC = 0x2710)
/// UTF-16BE(category)
/// u8(0x00)  // w0J = false (서버 버전 >= 20050126일 때)
/// ```
#[derive(Debug, Clone)]
pub struct CompactDataModuleRequest {
    /// ODI 파일명 (예: `"report.odi"`)
    pub odi_name: String,
    /// 카테고리 (예: `"/CM"`)
    pub category: String,
}

impl OzRequest for CompactDataModuleRequest {
    const CLASS_NAME: &'static str = "oz.framework.cp.message.FrameworkRequestDataModule";
    const TYPE_MARKER: Option<u32> = Some(0x17E);

    fn write_payload(&self, writer: &mut BufWriter) -> Result<()> {
        writer.write_utf16be(&self.odi_name)?;
        writer.write_u32(SUB_MAGIC)?;
        writer.write_utf16be(&self.category)?;
        writer.write_u8(0x00)?; // w0J = false (서버 버전 >= 20050126)
        Ok(())
    }
}

impl OzRequestResponse for CompactDataModuleRequest {
    type Response = DataModuleResponse;
}

impl OzResponse for DataModuleResponse {
    const CLASS_NAME: &'static str = "DataModule";

    fn parse_payload(reader: &mut BufReader, header: OzMessageHeader) -> Result<Self> {
        let payload_size = reader.read_i32()?;
        let _unknown1 = reader.read_i32()?;
        let _version_byte = reader.read_u8()?;

        let version = reader.read_i32()?;
        let prefix = reader.read_utf()?;
        if prefix != DATA_MODULE_PREFIX {
            return Err(OzError::InvalidPrefix {
                expected: DATA_MODULE_PREFIX.to_string(),
                actual: prefix,
            });
        }
        let data_version = reader.read_i32()?;
        let _unknown2 = reader.read_i32()?;
        let _unknown3 = reader.read_i32()?;

        let group_count = reader.read_i16()?;
        let mut groups = Vec::with_capacity(group_count as usize);
        for _ in 0..group_count {
            groups.push(parse_dataset_group(reader)?);
        }

        let total_data_size = reader.read_i32()?;

        let mut record_infos: Vec<Vec<RecordInfo>> = Vec::new();
        for group in &groups {
            for ds in &group.datasets {
                let mut ds_records = Vec::with_capacity(ds.row_count as usize);
                for _ in 0..ds.row_count {
                    let length = reader.read_i32()?;
                    let offset = reader.read_i32()?;
                    ds_records.push(RecordInfo { length, offset });
                }
                record_infos.push(ds_records);
            }
        }

        let data_start = reader.offset();
        let mut datasets: Vec<DataSet> = Vec::new();
        let mut ri_idx = 0;

        for group in &groups {
            let mut group_rows = Vec::new();
            for _ds in &group.datasets {
                for ri in &record_infos[ri_idx] {
                    // NOTE: Negative offset defense — guards against corrupted data
                    if ri.offset < 0 {
                        return Err(OzError::UnexpectedEof {
                            offset: data_start,
                            needed: 0,
                            available: reader.remaining(),
                        });
                    }
                    let abs_offset = data_start + ri.offset as usize;
                    reader.set_offset(abs_offset);
                    let row = read_row(reader, &group.fields)?;
                    group_rows.push(row);
                }
                ri_idx += 1;
            }
            datasets.push((group.name.clone(), group_rows));
        }

        let meta = DataModuleMeta {
            payload_size,
            version,
            data_version,
            group_count,
            total_data_size,
        };

        Ok(DataModuleResponse {
            header,
            meta,
            groups,
            datasets,
        })
    }

    /// DataModule 응답은 전체 바이너리를 직접 파싱합니다.
    ///
    /// 기본 `parse()` 구현을 사용합니다 (헤더 파싱 + 에러 체크 + 페이로드 파싱).
    fn parse(buf: &[u8]) -> Result<Self> {
        let mut reader = BufReader::new(buf);
        let header = parse_header(&mut reader)?;

        // 에러 응답 체크
        if header.class_name.contains(Self::EXCEPTION_PATTERN) {
            return Err(super::common::parse_exception(&mut reader)?);
        }

        Self::parse_payload(&mut reader, header)
    }
}

impl OzRequestResponse for DataModuleRequest {
    type Response = DataModuleResponse;
}

/// IBasicField를 파싱합니다.
///
/// 형식:
/// ```text
/// kind_raw = read_i32()       // 1=Normal, 2=Calculated
/// sql_type_raw = read_i32()   // SQL 타입 코드
/// name = read_utf()
/// nullable = read_bool()
/// if kind_raw == 2:
///   parsing_code = Some(read_utf())
/// ```
///
/// # Errors
///
/// - [`OzError::UnknownFieldKind`] — 알 수 없는 필드 종류
/// - [`OzError::UnknownSqlType`] — 알 수 없는 SQL 타입 코드
pub fn parse_basic_field(reader: &mut BufReader) -> Result<BasicField> {
    let kind_raw = reader.read_i32()?;
    let sql_type_raw = reader.read_i32()?;
    let name = reader.read_utf()?;
    let nullable = reader.read_bool()?;

    let parsing_code = if kind_raw == 2 {
        Some(reader.read_utf()?)
    } else {
        None
    };

    let kind = FieldKind::try_from(kind_raw)?;
    let sql_type = SqlType::try_from(sql_type_raw)?;

    Ok(BasicField {
        kind,
        sql_type,
        name,
        nullable,
        parsing_code,
    })
}

/// DataSetGroup 메타데이터를 파싱합니다.
///
/// 형식:
/// ```text
/// name = read_utf()
/// type_name = read_utf()
/// subtype = read_utf()
/// // IMetaSet - 주 필드 목록
/// field_count1 = read_i32()
/// fields = [parse_basic_field() for _ in 0..field_count1]
/// // ⚠️ IMetaSet - 보조 필드 목록 (반드시 읽어서 오프셋 전진!)
/// field_count2 = read_i32()
/// secondary_fields = [parse_basic_field() for _ in 0..field_count2]
/// // 데이터셋 정보
/// ds_count = read_i32()
/// datasets = [DataSetInfo for _ in 0..ds_count]
/// ```
pub fn parse_dataset_group(reader: &mut BufReader) -> Result<DataSetGroup> {
    let name = reader.read_utf()?;
    let type_name = reader.read_utf()?;
    let subtype = reader.read_utf()?;

    // NOTE: IMetaSet — primary field list
    let field_count1 = reader.read_i32()? as usize;
    let mut fields = Vec::with_capacity(field_count1);
    for _ in 0..field_count1 {
        fields.push(parse_basic_field(reader)?);
    }

    // NOTE: IMetaSet — secondary field list (must read to advance offset)
    let field_count2 = reader.read_i32()? as usize;
    let mut secondary_fields = Vec::with_capacity(field_count2);
    for _ in 0..field_count2 {
        secondary_fields.push(parse_basic_field(reader)?);
    }

    // 데이터셋 정보
    let ds_count = reader.read_i32()? as usize;
    let mut datasets = Vec::with_capacity(ds_count);
    for _ in 0..ds_count {
        let byte_size = reader.read_i32()?;
        let row_count = reader.read_i32()?;
        let key = reader.read_utf()?;
        datasets.push(DataSetInfo {
            byte_size,
            row_count,
            key,
        });
    }

    Ok(DataSetGroup {
        name,
        type_name,
        subtype,
        fields,
        secondary_fields,
        datasets,
    })
}

/// DataModule 응답 전체를 파싱합니다.
///
/// 전체 바이너리 버퍼를 받아 헤더 + 페이로드를 모두 파싱합니다.
///
/// # 파싱 단계
///
/// 1. 헤더 파싱 (`parse_header`)
/// 2. 페이로드 헤더 (payloadSize, unknown, versionByte)
/// 3. TTk 헤더 (version, prefix "OZBINDEDDATAMODULE" 검증)
/// 4. 그룹 메타데이터 N개
/// 5. RecordInfo 배열
/// 6. 데이터 blob에서 각 행 디코딩
///
/// # Errors
///
/// - [`OzError::InvalidMagic`] — 매직 넘버 불일치
/// - [`OzError::InvalidPrefix`] — prefix != "OZBINDEDDATAMODULE"
/// - [`OzError::UnexpectedEof`] — 버퍼 부족
pub fn parse_data_module(buf: &[u8]) -> Result<DataModuleResponse> {
    DataModuleResponse::parse(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        COMPACT_DATA_MODULE_TYPE_MARKER, DATA_MODULE_PREFIX, DATA_MODULE_TYPE_MARKER, MAGIC,
        REQUEST_FRAME_SIZE, SUB_MAGIC,
    };
    use crate::messages::common::parse_header;
    use crate::messages::traits::OzRequest;
    use crate::types::FieldValue;

    /// 테스트 헬퍼: DataModuleRequest를 빌드합니다.
    fn build_dm(
        odi_name: &str,
        category: &str,
        params: &[(String, String)],
        session_id: &str,
    ) -> Vec<u8> {
        let req = DataModuleRequest {
            odi_name: odi_name.to_string(),
            category: category.to_string(),
            params: params.to_vec(),
        };
        req.build(session_id).unwrap()
    }

    /// 테스트 헬퍼: CompactDataModuleRequest를 빌드합니다.
    fn build_compact_dm(odi_name: &str, category: &str, session_id: &str) -> Vec<u8> {
        let req = CompactDataModuleRequest {
            odi_name: odi_name.to_string(),
            category: category.to_string(),
        };
        req.build(session_id).unwrap()
    }

    #[test]
    fn test_data_module_request_class_name() {
        assert_eq!(
            DataModuleRequest::CLASS_NAME,
            "oz.framework.cp.message.FrameworkRequestDataModule"
        );
    }

    #[test]
    fn test_data_module_request_type_marker() {
        assert_eq!(DataModuleRequest::TYPE_MARKER, Some(0x17C));
    }

    #[test]
    fn test_build_data_module_request_size() {
        let params = vec![("arg1".to_string(), "2026".to_string())];
        let buf = build_dm("test.odi", "/CM", &params, "12345");
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_data_module_request_class_name() {
        let params = vec![];
        let buf = build_dm("test.odi", "/CM", &params, "12345");
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, DataModuleRequest::CLASS_NAME);
    }

    #[test]
    fn test_build_data_module_request_payload() {
        let params = vec![
            ("arg1".to_string(), "2026".to_string()),
            ("arg2".to_string(), "090".to_string()),
        ];
        let buf = build_dm("report.odi", "/CM", &params, "sess1");
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();

        // DataModule payload
        let type_marker = reader.read_u32().unwrap();
        assert_eq!(type_marker, DATA_MODULE_TYPE_MARKER);
        let odi_name = reader.read_utf16be().unwrap();
        assert_eq!(odi_name, "report.odi");
        let sub_magic = reader.read_u32().unwrap();
        assert_eq!(sub_magic, SUB_MAGIC);
        let category = reader.read_utf16be().unwrap();
        assert_eq!(category, "/CM");
        let bool1 = reader.read_u8().unwrap();
        assert_eq!(bool1, 0);
        let bool2 = reader.read_u8().unwrap();
        assert_eq!(bool2, 0);
        let empty_str = reader.read_utf16be().unwrap();
        assert_eq!(empty_str, "");
        let param_count = reader.read_u32().unwrap();
        assert_eq!(param_count, 2);
        let k1 = reader.read_utf16be().unwrap();
        let v1 = reader.read_utf16be().unwrap();
        assert_eq!(k1, "arg1");
        assert_eq!(v1, "2026");
        let k2 = reader.read_utf16be().unwrap();
        let v2 = reader.read_utf16be().unwrap();
        assert_eq!(k2, "arg2");
        assert_eq!(v2, "090");
        // trailing
        let t1 = reader.read_u32().unwrap();
        let t2 = reader.read_u32().unwrap();
        let t3 = reader.read_u32().unwrap();
        assert_eq!(t1, 2);
        assert_eq!(t2, 0x20);
        assert_eq!(t3, 0x11);
    }

    #[test]
    fn test_all_requests_exactly_9545_bytes() {
        let params = vec![("a".to_string(), "b".to_string())];
        let dm = build_dm("test.odi", "/CM", &params, "12345");
        assert_eq!(dm.len(), 9545);
    }

    #[test]
    fn test_roundtrip_data_module_request() {
        let params = vec![
            ("arg1".to_string(), "2026".to_string()),
            ("arg2".to_string(), "050".to_string()),
        ];
        let buf = build_dm("report.odi", "/CM", &params, "sess99");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.class_name, DataModuleRequest::CLASS_NAME);
        assert_eq!(header.get_field("s"), Some("sess99"));
    }

    #[test]
    fn test_parse_basic_field_normal() {
        let mut w = BufWriter::new();
        w.write_i32(1).unwrap(); // kind = Normal
        w.write_i32(12).unwrap(); // sql_type = VarChar
        w.write_utf("PSUBJ").unwrap(); // name
        w.write_bool(true).unwrap(); // nullable
        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let field = parse_basic_field(&mut reader).unwrap();
        assert_eq!(field.kind, FieldKind::Normal);
        assert_eq!(field.sql_type, SqlType::VarChar);
        assert_eq!(field.name, "PSUBJ");
        assert!(field.nullable);
        assert!(field.parsing_code.is_none());
    }

    #[test]
    fn test_parse_basic_field_calculated() {
        let mut w = BufWriter::new();
        w.write_i32(2).unwrap(); // kind = Calculated
        w.write_i32(4).unwrap(); // sql_type = Integer
        w.write_utf("CALC_FIELD").unwrap();
        w.write_bool(false).unwrap();
        w.write_utf("some_expr_code").unwrap(); // parsingCode
        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let field = parse_basic_field(&mut reader).unwrap();
        assert_eq!(field.kind, FieldKind::Calculated);
        assert_eq!(field.sql_type, SqlType::Integer);
        assert_eq!(field.name, "CALC_FIELD");
        assert!(!field.nullable);
        assert_eq!(field.parsing_code.as_deref(), Some("some_expr_code"));
    }

    #[test]
    fn test_parse_basic_field_unknown_kind() {
        let mut w = BufWriter::new();
        w.write_i32(3).unwrap(); // kind = invalid
        w.write_i32(12).unwrap();
        w.write_utf("BAD").unwrap();
        w.write_bool(false).unwrap();
        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let err = parse_basic_field(&mut reader).unwrap_err();
        assert!(matches!(err, OzError::UnknownFieldKind { kind: 3 }));
    }

    #[test]
    fn test_parse_basic_field_unknown_sql_type() {
        let mut w = BufWriter::new();
        w.write_i32(1).unwrap(); // Normal
        w.write_i32(9999).unwrap(); // unknown sql type
        w.write_utf("BAD").unwrap();
        w.write_bool(false).unwrap();
        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let err = parse_basic_field(&mut reader).unwrap_err();
        assert!(matches!(err, OzError::UnknownSqlType { code: 9999 }));
    }

    #[test]
    fn test_parse_dataset_group_with_dual_fields() {
        let mut w = BufWriter::new();
        // 그룹 메타
        w.write_utf("ET_DEPLAN").unwrap();
        w.write_utf("ByteArraySet").unwrap();
        w.write_utf("").unwrap(); // subtype

        // 주 필드 목록 (2개)
        w.write_i32(2).unwrap(); // field_count1
        // 필드 1: Normal VarChar "NAME"
        w.write_i32(1).unwrap();
        w.write_i32(12).unwrap();
        w.write_utf("NAME").unwrap();
        w.write_bool(true).unwrap();
        // 필드 2: Normal Integer "AGE"
        w.write_i32(1).unwrap();
        w.write_i32(4).unwrap();
        w.write_utf("AGE").unwrap();
        w.write_bool(true).unwrap();

        // 보조 필드 목록 (1개 — 반드시 읽어서 오프셋 전진)
        w.write_i32(1).unwrap(); // field_count2
        // 보조 필드: Normal VarChar "SECONDARY"
        w.write_i32(1).unwrap();
        w.write_i32(12).unwrap();
        w.write_utf("SECONDARY").unwrap();
        w.write_bool(false).unwrap();

        // 데이터셋 정보 (1개)
        w.write_i32(1).unwrap(); // ds_count
        w.write_i32(1024).unwrap(); // byte_size
        w.write_i32(5).unwrap(); // row_count
        w.write_utf("ds1").unwrap(); // key

        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let group = parse_dataset_group(&mut reader).unwrap();
        assert_eq!(group.name, "ET_DEPLAN");
        assert_eq!(group.type_name, "ByteArraySet");
        assert_eq!(group.subtype, "");
        assert_eq!(group.fields.len(), 2);
        assert_eq!(group.fields[0].name, "NAME");
        assert_eq!(group.fields[0].sql_type, SqlType::VarChar);
        assert_eq!(group.fields[1].name, "AGE");
        assert_eq!(group.fields[1].sql_type, SqlType::Integer);
        assert_eq!(group.secondary_fields.len(), 1);
        assert_eq!(group.secondary_fields[0].name, "SECONDARY");
        assert_eq!(group.datasets.len(), 1);
        assert_eq!(group.datasets[0].byte_size, 1024);
        assert_eq!(group.datasets[0].row_count, 5);
        assert_eq!(group.datasets[0].key, "ds1");

        // reader가 모든 데이터를 정확히 소비했는지 확인
        assert_eq!(reader.offset(), data.len());
    }

    #[test]
    fn test_parse_dataset_group_empty_fields() {
        let mut w = BufWriter::new();
        w.write_utf("EmptyGroup").unwrap();
        w.write_utf("Type").unwrap();
        w.write_utf("Sub").unwrap();
        w.write_i32(0).unwrap(); // field_count1 = 0
        w.write_i32(0).unwrap(); // field_count2 = 0
        w.write_i32(0).unwrap(); // ds_count = 0

        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let group = parse_dataset_group(&mut reader).unwrap();
        assert_eq!(group.name, "EmptyGroup");
        assert!(group.fields.is_empty());
        assert!(group.secondary_fields.is_empty());
        assert!(group.datasets.is_empty());
    }

    /// DataModule 응답 바이너리를 수동으로 생성합니다.
    fn build_test_data_module_response() -> Vec<u8> {
        let mut buf = Vec::with_capacity(4096);

        // === 헤더 ===
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let class_name = "TestDataModule";
        let u16_units: Vec<u16> = class_name.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&1u32.to_be_bytes());
        let key = "s";
        let val = "12345";
        for s in [key, val] {
            let units: Vec<u16> = s.encode_utf16().collect();
            buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
            for u in &units {
                buf.extend_from_slice(&u.to_be_bytes());
            }
        }

        // === 페이로드 헤더 ===
        buf.extend_from_slice(&380i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.push(0x01);

        // === TTk 헤더 ===
        buf.extend_from_slice(&17i32.to_be_bytes());
        let prefix = DATA_MODULE_PREFIX;
        buf.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(&2040i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        // === 그룹 메타데이터 ===
        buf.extend_from_slice(&1i16.to_be_bytes());

        // Group 1: "TestGroup"
        let group_name = "TestGroup";
        buf.extend_from_slice(&(group_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(group_name.as_bytes());
        let type_name = "ByteArraySet";
        buf.extend_from_slice(&(type_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(type_name.as_bytes());
        let subtype = "";
        buf.extend_from_slice(&(subtype.len() as u16).to_be_bytes());
        buf.extend_from_slice(subtype.as_bytes());

        // 주 필드 목록 (2개 필드)
        buf.extend_from_slice(&2i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&12i32.to_be_bytes());
        let fname1 = "NAME";
        buf.extend_from_slice(&(fname1.len() as u16).to_be_bytes());
        buf.extend_from_slice(fname1.as_bytes());
        buf.push(0x01);
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&4i32.to_be_bytes());
        let fname2 = "AGE";
        buf.extend_from_slice(&(fname2.len() as u16).to_be_bytes());
        buf.extend_from_slice(fname2.as_bytes());
        buf.push(0x01);

        // 보조 필드 목록 (0개)
        buf.extend_from_slice(&0i32.to_be_bytes());

        // 데이터셋 정보 (1개 데이터셋)
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&100i32.to_be_bytes());
        buf.extend_from_slice(&2i32.to_be_bytes());
        let ds_key = "ds0";
        buf.extend_from_slice(&(ds_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(ds_key.as_bytes());

        // === total_data_size ===
        buf.extend_from_slice(&100i32.to_be_bytes());

        // === RecordInfo[] (2행) ===
        let mut row1_data = Vec::new();
        row1_data.push(0x00); // VarChar not null
        let alice = "Alice";
        row1_data.extend_from_slice(&(alice.len() as u16).to_be_bytes());
        row1_data.extend_from_slice(alice.as_bytes());
        row1_data.extend_from_slice(&30i32.to_be_bytes()); // Integer: sentinel i32, no bool prefix

        let mut row2_data = Vec::new();
        row2_data.push(0x00); // VarChar not null
        let bob = "Bob";
        row2_data.extend_from_slice(&(bob.len() as u16).to_be_bytes());
        row2_data.extend_from_slice(bob.as_bytes());
        row2_data.extend_from_slice(&25i32.to_be_bytes()); // Integer: sentinel i32, no bool prefix

        let row1_offset = 0i32;
        let row2_offset = row1_data.len() as i32;

        buf.extend_from_slice(&(row1_data.len() as i32).to_be_bytes());
        buf.extend_from_slice(&row1_offset.to_be_bytes());
        buf.extend_from_slice(&(row2_data.len() as i32).to_be_bytes());
        buf.extend_from_slice(&row2_offset.to_be_bytes());

        // === 데이터 blob ===
        buf.extend_from_slice(&row1_data);
        buf.extend_from_slice(&row2_data);

        buf
    }

    #[test]
    fn test_parse_data_module_full() {
        let buf = build_test_data_module_response();
        let response = parse_data_module(&buf).unwrap();

        assert_eq!(response.header.magic, MAGIC);
        assert_eq!(response.header.class_name, "TestDataModule");
        assert_eq!(response.header.get_field("s"), Some("12345"));

        assert_eq!(response.meta.payload_size, 380);
        assert_eq!(response.meta.version, 17);
        assert_eq!(response.meta.data_version, 2040);
        assert_eq!(response.meta.group_count, 1);

        assert_eq!(response.groups.len(), 1);
        assert_eq!(response.groups[0].name, "TestGroup");
        assert_eq!(response.groups[0].type_name, "ByteArraySet");
        assert_eq!(response.groups[0].fields.len(), 2);
        assert_eq!(response.groups[0].fields[0].name, "NAME");
        assert_eq!(response.groups[0].fields[1].name, "AGE");

        assert_eq!(response.datasets.len(), 1);
        let (group_name, rows) = &response.datasets[0];
        assert_eq!(group_name, "TestGroup");
        assert_eq!(rows.len(), 2);

        assert_eq!(
            rows[0][0],
            ("NAME".to_string(), FieldValue::String("Alice".to_string()))
        );
        assert_eq!(rows[0][1], ("AGE".to_string(), FieldValue::Int(30)));

        assert_eq!(
            rows[1][0],
            ("NAME".to_string(), FieldValue::String("Bob".to_string()))
        );
        assert_eq!(rows[1][1], ("AGE".to_string(), FieldValue::Int(25)));
    }

    #[test]
    fn test_parse_data_module_invalid_prefix() {
        let mut buf = Vec::with_capacity(256);

        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "Test";
        let units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
        for u in &units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes());

        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.push(0x01);

        buf.extend_from_slice(&17i32.to_be_bytes());
        let bad_prefix = "WRONGPREFIX";
        buf.extend_from_slice(&(bad_prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(bad_prefix.as_bytes());

        let err = parse_data_module(&buf).unwrap_err();
        assert!(matches!(err, OzError::InvalidPrefix { .. }));
    }

    #[test]
    fn test_parse_data_module_with_nulls() {
        let mut buf = Vec::with_capacity(4096);

        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "NullTest";
        let units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
        for u in &units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes());

        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.push(0x01);

        buf.extend_from_slice(&17i32.to_be_bytes());
        let prefix = DATA_MODULE_PREFIX;
        buf.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(&2040i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        buf.extend_from_slice(&1i16.to_be_bytes());

        let gname = "NullGrp";
        buf.extend_from_slice(&(gname.len() as u16).to_be_bytes());
        buf.extend_from_slice(gname.as_bytes());
        let tname = "ByteArraySet";
        buf.extend_from_slice(&(tname.len() as u16).to_be_bytes());
        buf.extend_from_slice(tname.as_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&4i32.to_be_bytes());
        let fname = "VAL";
        buf.extend_from_slice(&(fname.len() as u16).to_be_bytes());
        buf.extend_from_slice(fname.as_bytes());
        buf.push(0x01);

        buf.extend_from_slice(&0i32.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&10i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        let dk = "d0";
        buf.extend_from_slice(&(dk.len() as u16).to_be_bytes());
        buf.extend_from_slice(dk.as_bytes());

        buf.extend_from_slice(&10i32.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        buf.extend_from_slice(&i32::MIN.to_be_bytes()); // Integer null = sentinel i32::MIN

        let response = parse_data_module(&buf).unwrap();
        let (_, rows) = &response.datasets[0];
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0].1, FieldValue::Null);
    }

    #[test]
    fn test_parse_data_module_multiple_groups() {
        let mut buf = Vec::with_capacity(4096);

        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "MultiGroup";
        let units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
        for u in &units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes());

        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.push(0x01);

        buf.extend_from_slice(&17i32.to_be_bytes());
        let prefix = DATA_MODULE_PREFIX;
        buf.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(&2040i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        buf.extend_from_slice(&2i16.to_be_bytes());

        // --- 그룹 1: "G1" with SmallInt field, 1 row ---
        let g1 = "G1";
        buf.extend_from_slice(&(g1.len() as u16).to_be_bytes());
        buf.extend_from_slice(g1.as_bytes());
        let t1 = "ByteArraySet";
        buf.extend_from_slice(&(t1.len() as u16).to_be_bytes());
        buf.extend_from_slice(t1.as_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&5i32.to_be_bytes());
        let f1 = "ID";
        buf.extend_from_slice(&(f1.len() as u16).to_be_bytes());
        buf.extend_from_slice(f1.as_bytes());
        buf.push(0x00);

        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&4i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        let dk1 = "d0";
        buf.extend_from_slice(&(dk1.len() as u16).to_be_bytes());
        buf.extend_from_slice(dk1.as_bytes());

        // --- 그룹 2: "G2" with Bit field, 1 row ---
        let g2 = "G2";
        buf.extend_from_slice(&(g2.len() as u16).to_be_bytes());
        buf.extend_from_slice(g2.as_bytes());
        let t2 = "ByteArraySet";
        buf.extend_from_slice(&(t2.len() as u16).to_be_bytes());
        buf.extend_from_slice(t2.as_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&(-7i32).to_be_bytes());
        let f2 = "FLAG";
        buf.extend_from_slice(&(f2.len() as u16).to_be_bytes());
        buf.extend_from_slice(f2.as_bytes());
        buf.push(0x00);

        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        let dk2 = "d1";
        buf.extend_from_slice(&(dk2.len() as u16).to_be_bytes());
        buf.extend_from_slice(dk2.as_bytes());

        buf.extend_from_slice(&10i32.to_be_bytes());

        let row1_data: Vec<u8> = {
            let mut v = vec![0x00]; // SmallInt: bool prefix not null
            v.extend_from_slice(&42i32.to_be_bytes());
            v
        };
        let row2_data: Vec<u8> = vec![0x01];

        buf.extend_from_slice(&(row1_data.len() as i32).to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        let row2_offset = row1_data.len() as i32;
        buf.extend_from_slice(&(row2_data.len() as i32).to_be_bytes());
        buf.extend_from_slice(&row2_offset.to_be_bytes());

        buf.extend_from_slice(&row1_data);
        buf.extend_from_slice(&row2_data);

        let response = parse_data_module(&buf).unwrap();
        assert_eq!(response.datasets.len(), 2);
        assert_eq!(response.datasets[0].0, "G1");
        assert_eq!(response.datasets[1].0, "G2");
        assert_eq!(
            response.datasets[0].1[0][0],
            ("ID".to_string(), FieldValue::Int(42))
        );
        assert_eq!(
            response.datasets[1].1[0][0],
            ("FLAG".to_string(), FieldValue::Bool(true))
        );
    }

    #[test]
    fn test_parse_data_module_negative_record_offset() {
        let mut buf = Vec::with_capacity(4096);

        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "NegOff";
        let units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
        for u in &units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes());

        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.push(0x01);

        buf.extend_from_slice(&17i32.to_be_bytes());
        let prefix = DATA_MODULE_PREFIX;
        buf.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(&2040i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        buf.extend_from_slice(&1i16.to_be_bytes());
        let gname = "G";
        buf.extend_from_slice(&(gname.len() as u16).to_be_bytes());
        buf.extend_from_slice(gname.as_bytes());
        let tname = "ByteArraySet";
        buf.extend_from_slice(&(tname.len() as u16).to_be_bytes());
        buf.extend_from_slice(tname.as_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&4i32.to_be_bytes());
        let fname = "V";
        buf.extend_from_slice(&(fname.len() as u16).to_be_bytes());
        buf.extend_from_slice(fname.as_bytes());
        buf.push(0x00);

        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&10i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        let dk = "d";
        buf.extend_from_slice(&(dk.len() as u16).to_be_bytes());
        buf.extend_from_slice(dk.as_bytes());

        buf.extend_from_slice(&10i32.to_be_bytes());

        // RecordInfo with 음수 오프셋!
        buf.extend_from_slice(&5i32.to_be_bytes());
        buf.extend_from_slice(&(-1i32).to_be_bytes());

        buf.extend_from_slice(&42i32.to_be_bytes()); // Integer: sentinel i32, no bool prefix

        let err = parse_data_module(&buf).unwrap_err();
        assert!(matches!(err, OzError::UnexpectedEof { .. }));
    }

    // ==================== CompactDataModuleRequest (382) 테스트 ====================

    #[test]
    fn test_compact_data_module_request_class_name() {
        assert_eq!(
            CompactDataModuleRequest::CLASS_NAME,
            "oz.framework.cp.message.FrameworkRequestDataModule"
        );
        // 380과 동일한 클래스명
        assert_eq!(
            CompactDataModuleRequest::CLASS_NAME,
            DataModuleRequest::CLASS_NAME
        );
    }

    #[test]
    fn test_compact_data_module_request_type_marker() {
        assert_eq!(CompactDataModuleRequest::TYPE_MARKER, Some(0x17E));
        // 380(0x17C)과 다른 마커
        assert_ne!(
            CompactDataModuleRequest::TYPE_MARKER,
            DataModuleRequest::TYPE_MARKER
        );
    }

    #[test]
    fn test_build_compact_data_module_request_size() {
        let buf = build_compact_dm("test.odi", "/CM", "12345");
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_compact_data_module_request_class_name() {
        let buf = build_compact_dm("test.odi", "/CM", "12345");
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, CompactDataModuleRequest::CLASS_NAME);
    }

    #[test]
    fn test_build_compact_data_module_request_payload() {
        let buf = build_compact_dm("report.odi", "/CM", "sess1");
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();

        // Type marker = 382 (0x17E)
        let type_marker = reader.read_u32().unwrap();
        assert_eq!(type_marker, COMPACT_DATA_MODULE_TYPE_MARKER);

        // odi_name
        let odi_name = reader.read_utf16be().unwrap();
        assert_eq!(odi_name, "report.odi");

        // sub_magic
        let sub_magic = reader.read_u32().unwrap();
        assert_eq!(sub_magic, SUB_MAGIC);

        // category
        let category = reader.read_utf16be().unwrap();
        assert_eq!(category, "/CM");

        // w0J = false
        let w0j = reader.read_u8().unwrap();
        assert_eq!(w0j, 0);

        // 382에는 trailing constants가 없으므로, 이후 바이트는 모두 0 패딩이어야 함
        let remaining = &buf[reader.offset()..];
        assert!(
            remaining.iter().all(|&b| b == 0),
            "382 페이로드 이후 바이트는 모두 0 패딩이어야 합니다"
        );
    }

    #[test]
    fn test_compact_vs_standard_payload_size() {
        // 382(compact)는 380(standard)보다 페이로드가 작아야 합니다.
        // 프레임 크기는 동일하지만, 의미 있는 바이트(non-zero)가 더 적습니다.
        let params = vec![("arg1".to_string(), "2026".to_string())];
        let standard = build_dm("test.odi", "/CM", &params, "12345");
        let compact = build_compact_dm("test.odi", "/CM", "12345");

        // 프레임 크기는 동일
        assert_eq!(standard.len(), compact.len());
        assert_eq!(standard.len(), REQUEST_FRAME_SIZE);

        // compact의 non-zero 바이트가 standard보다 적어야 함
        let standard_nonzero = standard.iter().filter(|&&b| b != 0).count();
        let compact_nonzero = compact.iter().filter(|&&b| b != 0).count();
        assert!(
            compact_nonzero < standard_nonzero,
            "compact({}) should have fewer non-zero bytes than standard({})",
            compact_nonzero,
            standard_nonzero
        );
    }

    #[test]
    fn test_compact_roundtrip_header() {
        let buf = build_compact_dm("report.odi", "/CM", "sess42");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.class_name, CompactDataModuleRequest::CLASS_NAME);
        assert_eq!(header.get_field("s"), Some("sess42"));
    }
}

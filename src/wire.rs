//! 저수준 바이너리 I/O 모듈 — Big Endian 기본 타입과 OZ 프로토콜 문자열 읽기/쓰기
//!
//! [`BufReader`]는 `&[u8]` 슬라이스로부터 순차적으로 바이너리 데이터를 읽고,
//! [`BufWriter`]는 고정 크기 버퍼에 순차적으로 바이너리 데이터를 씁니다.
//!
//! ## 문자열 인코딩
//!
//! OZ 프로토콜은 두 가지 문자열 인코딩을 사용합니다:
//!
//! - **UTF-16BE** ([`BufReader::read_utf16be`]): `[4B charCount] + [N×2B UTF-16BE]`
//!   길이 프리픽스가 **문자 수**임에 주의 (바이트 수 아님!)
//! - **Java Modified UTF-8** ([`BufReader::read_utf`]): `[2B byteLength] + [NB UTF-8]`
//!   null 문자가 `0xC0 0x80`으로 인코딩될 수 있음

use crate::constants::REQUEST_FRAME_SIZE;
use crate::error::{OzError, Result};

/// Java Modified UTF-8 (CESU-8) 바이트 시퀀스를 Rust [`String`]으로 변환합니다.
///
/// `cesu8` 크레이트를 사용하여 Java Modified UTF-8을 디코딩합니다.
/// 이 인코딩에서 null 문자(`\0`)는 `0xC0 0x80`으로, 보충 문자는 surrogate pair로 인코딩됩니다.
fn decode_modified_utf8(bytes: &[u8]) -> Result<String> {
    cesu8::from_java_cesu8(bytes)
        .map(|cow| cow.into_owned())
        .map_err(|_| OzError::InvalidCesu8)
}

/// `&[u8]` 슬라이스와 오프셋을 관리하며 순차적 Big Endian 바이너리 읽기를 제공합니다.
///
/// 모든 읽기 메서드는 버퍼 경계를 초과하면 [`OzError::UnexpectedEof`]를 반환합니다.
///
/// # 예시
///
/// ```
/// use ozra::wire::BufReader;
///
/// let data = [0x00, 0x00, 0x27, 0x11]; // MAGIC = 0x00002711
/// let mut reader = BufReader::new(&data);
/// assert_eq!(reader.read_u32().unwrap(), 0x00002711);
/// assert_eq!(reader.remaining(), 0);
/// ```
pub struct BufReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> BufReader<'a> {
    /// 바이트 슬라이스로부터 새 리더를 생성합니다. 초기 오프셋은 0입니다.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// 현재 읽기 오프셋을 반환합니다.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// 읽기 위치를 임의로 설정합니다 (data blob 접근 등에 사용).
    ///
    /// `pos`가 버퍼 길이를 초과하면 버퍼 끝으로 클램핑합니다.
    pub fn set_offset(&mut self, pos: usize) {
        self.offset = pos.min(self.buf.len());
    }

    /// 남은 바이트 수를 반환합니다.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    /// 현재 위치에서 `needed` 바이트를 읽을 수 있는지 확인합니다.
    /// 불가능하면 [`OzError::UnexpectedEof`]를 반환합니다.
    #[inline]
    fn ensure(&self, needed: usize) -> Result<()> {
        let available = self.remaining();
        if available < needed {
            return Err(OzError::UnexpectedEof {
                offset: self.offset,
                needed,
                available,
            });
        }
        Ok(())
    }

    /// 1바이트 부호 없는 정수를 읽습니다.
    pub fn read_u8(&mut self) -> Result<u8> {
        self.ensure(1)?;
        let v = self.buf[self.offset];
        self.offset += 1;
        Ok(v)
    }

    /// 1바이트를 읽어 불리언으로 반환합니다 (`!= 0`이면 `true`).
    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    /// 2바이트 Big Endian 부호 있는 정수를 읽습니다.
    pub fn read_i16(&mut self) -> Result<i16> {
        self.ensure(2)?;
        let v = i16::from_be_bytes([self.buf[self.offset], self.buf[self.offset + 1]]);
        self.offset += 2;
        Ok(v)
    }

    /// 2바이트 Big Endian 부호 없는 정수를 읽습니다.
    pub fn read_u16(&mut self) -> Result<u16> {
        self.ensure(2)?;
        let v = u16::from_be_bytes([self.buf[self.offset], self.buf[self.offset + 1]]);
        self.offset += 2;
        Ok(v)
    }

    /// 4바이트 Big Endian 부호 있는 정수를 읽습니다.
    pub fn read_i32(&mut self) -> Result<i32> {
        self.ensure(4)?;
        let v = i32::from_be_bytes([
            self.buf[self.offset],
            self.buf[self.offset + 1],
            self.buf[self.offset + 2],
            self.buf[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(v)
    }

    /// 4바이트 Big Endian 부호 없는 정수를 읽습니다.
    pub fn read_u32(&mut self) -> Result<u32> {
        self.ensure(4)?;
        let v = u32::from_be_bytes([
            self.buf[self.offset],
            self.buf[self.offset + 1],
            self.buf[self.offset + 2],
            self.buf[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(v)
    }

    /// 8바이트 Big Endian 부호 있는 정수를 읽습니다.
    pub fn read_i64(&mut self) -> Result<i64> {
        self.ensure(8)?;
        let v = i64::from_be_bytes([
            self.buf[self.offset],
            self.buf[self.offset + 1],
            self.buf[self.offset + 2],
            self.buf[self.offset + 3],
            self.buf[self.offset + 4],
            self.buf[self.offset + 5],
            self.buf[self.offset + 6],
            self.buf[self.offset + 7],
        ]);
        self.offset += 8;
        Ok(v)
    }

    /// 4바이트 Big Endian IEEE 754 단정밀도 부동소수점을 읽습니다.
    pub fn read_f32(&mut self) -> Result<f32> {
        self.ensure(4)?;
        let v = f32::from_be_bytes([
            self.buf[self.offset],
            self.buf[self.offset + 1],
            self.buf[self.offset + 2],
            self.buf[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(v)
    }

    /// 8바이트 Big Endian IEEE 754 배정밀도 부동소수점을 읽습니다.
    pub fn read_f64(&mut self) -> Result<f64> {
        self.ensure(8)?;
        let v = f64::from_be_bytes([
            self.buf[self.offset],
            self.buf[self.offset + 1],
            self.buf[self.offset + 2],
            self.buf[self.offset + 3],
            self.buf[self.offset + 4],
            self.buf[self.offset + 5],
            self.buf[self.offset + 6],
            self.buf[self.offset + 7],
        ]);
        self.offset += 8;
        Ok(v)
    }

    /// 지정 길이의 원시 바이트 슬라이스를 zero-copy로 읽습니다.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        self.ensure(len)?;
        let slice = &self.buf[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    /// UTF-16BE 문자열을 읽습니다.
    ///
    /// 형식: `[4B charCount] + [charCount × 2B UTF-16BE]`
    ///
    /// **주의**: 길이 프리픽스는 **문자 수**이며, 바이트 수가 아닙니다.
    pub fn read_utf16be(&mut self) -> Result<String> {
        let char_count = self.read_u32()? as usize;
        let byte_len = char_count.checked_mul(2).ok_or(OzError::UnexpectedEof {
            offset: self.offset,
            needed: usize::MAX,
            available: self.remaining(),
        })?;
        self.ensure(byte_len)?;

        let start_offset = self.offset;
        let mut u16_buf = Vec::with_capacity(char_count);
        for i in 0..char_count {
            let hi = self.buf[self.offset + i * 2];
            let lo = self.buf[self.offset + i * 2 + 1];
            u16_buf.push(u16::from_be_bytes([hi, lo]));
        }
        self.offset += byte_len;

        String::from_utf16(&u16_buf).map_err(|_| OzError::InvalidUtf16 {
            offset: start_offset,
            detail: format!(
                "invalid UTF-16BE sequence ({} chars at offset {})",
                char_count, start_offset
            ),
        })
    }

    /// Java Modified UTF-8 문자열을 읽습니다.
    ///
    /// 형식: `[2B byteLength] + [byteLength × 1B UTF-8]`
    ///
    /// Java Modified UTF-8에서 null 문자(`\0`)는 `0xC0 0x80`으로 인코딩될 수 있습니다.
    pub fn read_utf(&mut self) -> Result<String> {
        let byte_len = self.read_u16()? as usize;
        let bytes = self.read_bytes(byte_len)?;
        decode_modified_utf8(bytes)
    }
}

/// 고정 크기 버퍼에 순차적 Big Endian 바이너리 쓰기를 제공합니다.
///
/// 기본적으로 [`REQUEST_FRAME_SIZE`] (9,545바이트) 크기의 0-초기화 버퍼를 사용합니다.
/// 모든 쓰기 메서드는 버퍼 경계를 초과하면 [`OzError::BufferOverflow`]를 반환합니다.
///
/// # 예시
///
/// ```
/// use ozra::wire::BufWriter;
///
/// let mut writer = BufWriter::new();
/// writer.write_u32(0x00002711).unwrap();
/// assert_eq!(&writer.as_bytes()[..4], &[0x00, 0x00, 0x27, 0x11]);
/// ```
pub struct BufWriter {
    buf: Vec<u8>,
    offset: usize,
}

impl BufWriter {
    /// [`REQUEST_FRAME_SIZE`] (9,545바이트) 크기의 0-초기화 버퍼를 생성합니다.
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; REQUEST_FRAME_SIZE],
            offset: 0,
        }
    }

    /// 현재 쓰기 오프셋을 반환합니다.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// 현재 위치에서 `needed` 바이트를 쓸 수 있는지 확인합니다.
    /// 불가능하면 [`OzError::BufferOverflow`]를 반환합니다.
    #[inline]
    fn ensure(&self, needed: usize) -> Result<()> {
        if self.offset + needed > self.buf.len() {
            return Err(OzError::BufferOverflow {
                offset: self.offset,
                needed,
                limit: self.buf.len(),
            });
        }
        Ok(())
    }

    /// 1바이트 부호 없는 정수를 씁니다.
    pub fn write_u8(&mut self, v: u8) -> Result<()> {
        self.ensure(1)?;
        self.buf[self.offset] = v;
        self.offset += 1;
        Ok(())
    }

    /// 1바이트 불리언을 씁니다 (`true` → `1`, `false` → `0`).
    pub fn write_bool(&mut self, v: bool) -> Result<()> {
        self.write_u8(if v { 1 } else { 0 })
    }

    /// 2바이트 Big Endian 부호 있는 정수를 씁니다.
    pub fn write_i16(&mut self, v: i16) -> Result<()> {
        self.ensure(2)?;
        let bytes = v.to_be_bytes();
        self.buf[self.offset..self.offset + 2].copy_from_slice(&bytes);
        self.offset += 2;
        Ok(())
    }

    /// 2바이트 Big Endian 부호 없는 정수를 씁니다.
    pub fn write_u16(&mut self, v: u16) -> Result<()> {
        self.ensure(2)?;
        let bytes = v.to_be_bytes();
        self.buf[self.offset..self.offset + 2].copy_from_slice(&bytes);
        self.offset += 2;
        Ok(())
    }

    /// 4바이트 Big Endian 부호 있는 정수를 씁니다.
    pub fn write_i32(&mut self, v: i32) -> Result<()> {
        self.ensure(4)?;
        let bytes = v.to_be_bytes();
        self.buf[self.offset..self.offset + 4].copy_from_slice(&bytes);
        self.offset += 4;
        Ok(())
    }

    /// 4바이트 Big Endian 부호 없는 정수를 씁니다.
    pub fn write_u32(&mut self, v: u32) -> Result<()> {
        self.ensure(4)?;
        let bytes = v.to_be_bytes();
        self.buf[self.offset..self.offset + 4].copy_from_slice(&bytes);
        self.offset += 4;
        Ok(())
    }

    /// UTF-16BE 문자열을 씁니다.
    ///
    /// 형식: `[4B charCount] + [charCount × 2B UTF-16BE]`
    ///
    /// Rust `str`의 `.encode_utf16()`을 사용하여 서로게이트 페어를 올바르게 처리합니다.
    pub fn write_utf16be(&mut self, s: &str) -> Result<()> {
        let u16_units: Vec<u16> = s.encode_utf16().collect();
        let char_count = u16_units.len();
        let data_bytes = char_count.checked_mul(2).ok_or(OzError::BufferOverflow {
            offset: self.offset,
            needed: usize::MAX,
            limit: self.buf.len(),
        })?;
        let total_needed = 4 + data_bytes;
        self.ensure(total_needed)?;

        // charCount 기록
        let count_bytes = (char_count as u32).to_be_bytes();
        self.buf[self.offset..self.offset + 4].copy_from_slice(&count_bytes);
        self.offset += 4;

        // UTF-16BE 코드 유닛 기록
        for unit in &u16_units {
            let bytes = unit.to_be_bytes();
            self.buf[self.offset..self.offset + 2].copy_from_slice(&bytes);
            self.offset += 2;
        }
        Ok(())
    }

    /// Java Modified UTF-8 문자열을 씁니다.
    ///
    /// 형식: `[2B byteLength] + [byteLength × 1B UTF-8]`
    ///
    /// 현재 구현은 표준 UTF-8로 기록합니다. null 문자(`\0`)가 포함된 문자열의 경우
    /// `0xC0 0x80`으로 인코딩합니다.
    pub fn write_utf(&mut self, s: &str) -> Result<()> {
        // NOTE: Encodes null chars as 0xC0 0x80 for Modified UTF-8
        let mut utf8_bytes = Vec::with_capacity(s.len());
        for byte in s.as_bytes() {
            if *byte == 0x00 {
                utf8_bytes.push(0xC0);
                utf8_bytes.push(0x80);
            } else {
                utf8_bytes.push(*byte);
            }
        }

        let byte_len = utf8_bytes.len();
        let total_needed = 2 + byte_len;
        self.ensure(total_needed)?;

        // byteLength 기록 (2B)
        let len_bytes = (byte_len as u16).to_be_bytes();
        self.buf[self.offset..self.offset + 2].copy_from_slice(&len_bytes);
        self.offset += 2;

        // UTF-8 바이트 기록
        self.buf[self.offset..self.offset + byte_len].copy_from_slice(&utf8_bytes);
        self.offset += byte_len;
        Ok(())
    }

    /// 원시 바이트 슬라이스를 씁니다.
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.ensure(data.len())?;
        self.buf[self.offset..self.offset + data.len()].copy_from_slice(data);
        self.offset += data.len();
        Ok(())
    }

    /// 8바이트 Big Endian 부호 있는 정수를 씁니다.
    pub fn write_i64(&mut self, v: i64) -> Result<()> {
        self.ensure(8)?;
        let bytes = v.to_be_bytes();
        self.buf[self.offset..self.offset + 8].copy_from_slice(&bytes);
        self.offset += 8;
        Ok(())
    }

    /// 4바이트 Big Endian IEEE 754 단정밀도 부동소수점을 씁니다.
    pub fn write_f32(&mut self, v: f32) -> Result<()> {
        self.ensure(4)?;
        let bytes = v.to_be_bytes();
        self.buf[self.offset..self.offset + 4].copy_from_slice(&bytes);
        self.offset += 4;
        Ok(())
    }

    /// 8바이트 Big Endian IEEE 754 배정밀도 부동소수점을 씁니다.
    pub fn write_f64(&mut self, v: f64) -> Result<()> {
        self.ensure(8)?;
        let bytes = v.to_be_bytes();
        self.buf[self.offset..self.offset + 8].copy_from_slice(&bytes);
        self.offset += 8;
        Ok(())
    }

    /// 내부 버퍼를 소비하여 [`Vec<u8>`]로 반환합니다.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// 현재 버퍼의 바이트 슬라이스 참조를 반환합니다.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

impl Default for BufWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u8_basic() {
        let data = [0x42];
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_u8().unwrap(), 0x42);
        assert_eq!(r.offset(), 1);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn read_bool_true_and_false() {
        let data = [0x01, 0x00, 0xFF];
        let mut r = BufReader::new(&data);
        assert!(r.read_bool().unwrap());
        assert!(!r.read_bool().unwrap());
        assert!(r.read_bool().unwrap()); // 0xFF != 0 → true
    }

    #[test]
    fn read_i16_big_endian() {
        let data = [0xFF, 0xFE]; // -2 in i16 BE
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_i16().unwrap(), -2);
    }

    #[test]
    fn read_u16_big_endian() {
        let data = [0x01, 0x00]; // 256 in u16 BE
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_u16().unwrap(), 256);
    }

    #[test]
    fn read_i32_big_endian() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF]; // -1 in i32 BE
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_i32().unwrap(), -1);
    }

    #[test]
    fn read_u32_magic() {
        let data = [0x00, 0x00, 0x27, 0x11]; // MAGIC = 0x00002711
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_u32().unwrap(), crate::constants::MAGIC);
    }

    #[test]
    fn read_i64_big_endian() {
        let data = 42i64.to_be_bytes();
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_i64().unwrap(), 42);
    }

    #[test]
    fn read_i64_negative() {
        let data = (-1i64).to_be_bytes();
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_i64().unwrap(), -1);
    }

    #[test]
    fn read_f32_big_endian() {
        let data = std::f32::consts::PI.to_be_bytes();
        let mut r = BufReader::new(&data);
        let v = r.read_f32().unwrap();
        assert!((v - std::f32::consts::PI).abs() < f32::EPSILON);
    }

    #[test]
    fn read_f64_big_endian() {
        let data = std::f64::consts::PI.to_be_bytes();
        let mut r = BufReader::new(&data);
        let v = r.read_f64().unwrap();
        assert!((v - std::f64::consts::PI).abs() < f64::EPSILON);
    }

    #[test]
    fn read_bytes_zero_copy() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut r = BufReader::new(&data);
        let slice = r.read_bytes(3).unwrap();
        assert_eq!(slice, &[0x01, 0x02, 0x03]);
        assert_eq!(r.offset(), 3);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn read_utf16be_ascii() {
        // "guest" → 5 chars
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes()); // charCount = 5
        for ch in "guest".encode_utf16() {
            buf.extend_from_slice(&ch.to_be_bytes());
        }
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf16be().unwrap(), "guest");
    }

    #[test]
    fn read_utf16be_korean() {
        // "강의계획서" → 5 chars
        let mut buf = Vec::new();
        let s = "강의계획서";
        let u16_units: Vec<u16> = s.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for ch in &u16_units {
            buf.extend_from_slice(&ch.to_be_bytes());
        }
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf16be().unwrap(), "강의계획서");
    }

    #[test]
    fn read_utf16be_empty_string() {
        let buf = 0u32.to_be_bytes(); // charCount = 0
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf16be().unwrap(), "");
    }

    #[test]
    fn utf16be_length_is_char_count_not_byte_count() {
        // "AB" → charCount=2, byteLen=4
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_be_bytes()); // charCount = 2
        buf.extend_from_slice(&0x0041u16.to_be_bytes()); // 'A'
        buf.extend_from_slice(&0x0042u16.to_be_bytes()); // 'B'
        let mut r = BufReader::new(&buf);
        let s = r.read_utf16be().unwrap();
        assert_eq!(s, "AB");
        assert_eq!(r.offset(), 8); // 4 (charCount) + 4 (2 chars × 2B)
    }

    #[test]
    fn read_utf_basic() {
        let s = "hello";
        let mut buf = Vec::new();
        buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf().unwrap(), "hello");
    }

    #[test]
    fn read_utf_korean() {
        let s = "강의계획서";
        let bytes = s.as_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(bytes);
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf().unwrap(), "강의계획서");
    }

    #[test]
    fn read_utf_empty() {
        let buf = [0x00, 0x00]; // byteLen = 0
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf().unwrap(), "");
    }

    #[test]
    fn read_utf_null_char_modified_utf8() {
        // Java Modified UTF-8: null 문자 → 0xC0 0x80
        let mut buf = Vec::new();
        let payload = [0x41, 0xC0, 0x80, 0x42]; // "A\0B"
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&payload);
        let mut r = BufReader::new(&buf);
        let result = r.read_utf().unwrap();
        assert_eq!(result, "A\0B");
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn read_u8_eof() {
        let data: [u8; 0] = [];
        let mut r = BufReader::new(&data);
        let err = r.read_u8().unwrap_err();
        assert!(matches!(
            err,
            OzError::UnexpectedEof {
                offset: 0,
                needed: 1,
                available: 0
            }
        ));
    }

    #[test]
    fn read_u32_insufficient_bytes() {
        let data = [0x00, 0x01]; // 2 bytes, need 4
        let mut r = BufReader::new(&data);
        let err = r.read_u32().unwrap_err();
        assert!(matches!(
            err,
            OzError::UnexpectedEof {
                offset: 0,
                needed: 4,
                available: 2
            }
        ));
    }

    #[test]
    fn read_i64_eof_after_partial() {
        let data = [0x00; 4]; // 4 bytes, need 8
        let mut r = BufReader::new(&data);
        let err = r.read_i64().unwrap_err();
        assert!(matches!(
            err,
            OzError::UnexpectedEof {
                offset: 0,
                needed: 8,
                available: 4
            }
        ));
    }

    #[test]
    fn reader_offset_advances_correctly() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x12u8.to_be_bytes()); // 1B
        buf.extend_from_slice(&0x1234u16.to_be_bytes()); // 2B
        buf.extend_from_slice(&0x12345678u32.to_be_bytes()); // 4B
        buf.extend_from_slice(&42i64.to_be_bytes()); // 8B

        let mut r = BufReader::new(&buf);
        assert_eq!(r.offset(), 0);

        r.read_u8().unwrap();
        assert_eq!(r.offset(), 1);

        r.read_u16().unwrap();
        assert_eq!(r.offset(), 3);

        r.read_u32().unwrap();
        assert_eq!(r.offset(), 7);

        r.read_i64().unwrap();
        assert_eq!(r.offset(), 15);

        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn reader_set_offset() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04];
        let mut r = BufReader::new(&data);
        r.set_offset(3);
        assert_eq!(r.offset(), 3);
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.read_u8().unwrap(), 0x03);
    }

    #[test]
    fn write_u8_basic() {
        let mut w = BufWriter::new();
        w.write_u8(0x42).unwrap();
        assert_eq!(w.as_bytes()[0], 0x42);
        assert_eq!(w.offset(), 1);
    }

    #[test]
    fn write_bool_values() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        w.write_bool(false).unwrap();
        assert_eq!(w.as_bytes()[0], 1);
        assert_eq!(w.as_bytes()[1], 0);
    }

    #[test]
    fn write_i16_big_endian() {
        let mut w = BufWriter::new();
        w.write_i16(-2).unwrap();
        assert_eq!(&w.as_bytes()[..2], &[0xFF, 0xFE]);
    }

    #[test]
    fn write_u16_big_endian() {
        let mut w = BufWriter::new();
        w.write_u16(256).unwrap();
        assert_eq!(&w.as_bytes()[..2], &[0x01, 0x00]);
    }

    #[test]
    fn write_i32_big_endian() {
        let mut w = BufWriter::new();
        w.write_i32(-1).unwrap();
        assert_eq!(&w.as_bytes()[..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn write_u32_magic() {
        let mut w = BufWriter::new();
        w.write_u32(crate::constants::MAGIC).unwrap();
        assert_eq!(&w.as_bytes()[..4], &[0x00, 0x00, 0x27, 0x11]);
    }

    #[test]
    fn write_utf16be_ascii() {
        let mut w = BufWriter::new();
        w.write_utf16be("guest").unwrap();
        // charCount = 5
        assert_eq!(&w.as_bytes()[..4], &5u32.to_be_bytes());
        // 'g' = 0x0067
        assert_eq!(&w.as_bytes()[4..6], &[0x00, 0x67]);
        assert_eq!(w.offset(), 4 + 5 * 2); // 14
    }

    #[test]
    fn write_utf16be_korean() {
        let mut w = BufWriter::new();
        w.write_utf16be("강의계획서").unwrap();
        // charCount = 5
        assert_eq!(&w.as_bytes()[..4], &5u32.to_be_bytes());
        assert_eq!(w.offset(), 4 + 5 * 2); // 14
    }

    #[test]
    fn write_utf16be_empty() {
        let mut w = BufWriter::new();
        w.write_utf16be("").unwrap();
        assert_eq!(&w.as_bytes()[..4], &0u32.to_be_bytes());
        assert_eq!(w.offset(), 4);
    }

    #[test]
    fn write_utf_basic() {
        let mut w = BufWriter::new();
        w.write_utf("hello").unwrap();
        assert_eq!(&w.as_bytes()[..2], &5u16.to_be_bytes());
        assert_eq!(&w.as_bytes()[2..7], b"hello");
        assert_eq!(w.offset(), 7);
    }

    #[test]
    fn write_utf_empty() {
        let mut w = BufWriter::new();
        w.write_utf("").unwrap();
        assert_eq!(&w.as_bytes()[..2], &0u16.to_be_bytes());
        assert_eq!(w.offset(), 2);
    }

    #[test]
    fn write_utf_null_char_modified_utf8() {
        let mut w = BufWriter::new();
        w.write_utf("A\0B").unwrap();
        // "A\0B" → 0x41, 0xC0, 0x80, 0x42 (4 bytes in Modified UTF-8)
        assert_eq!(&w.as_bytes()[..2], &4u16.to_be_bytes()); // byteLen = 4
        assert_eq!(&w.as_bytes()[2..6], &[0x41, 0xC0, 0x80, 0x42]);
        assert_eq!(w.offset(), 6);
    }

    #[test]
    fn writer_overflow_u8() {
        let mut w = BufWriter::new();
        // 오프셋을 끝까지 이동
        w.offset = REQUEST_FRAME_SIZE;
        let err = w.write_u8(0x00).unwrap_err();
        assert!(matches!(
            err,
            OzError::BufferOverflow {
                offset,
                needed: 1,
                limit,
            } if offset == REQUEST_FRAME_SIZE && limit == REQUEST_FRAME_SIZE
        ));
    }

    #[test]
    fn writer_overflow_u32() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 2; // 2 bytes left, need 4
        let err = w.write_u32(0).unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { needed: 4, .. }));
    }

    #[test]
    fn writer_overflow_utf16be() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 5; // 5 bytes left, need 4 + 2 = 6
        let err = w.write_utf16be("A").unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { .. }));
    }

    #[test]
    fn writer_overflow_utf() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 2; // 2 bytes left, need 2 + 5 = 7
        let err = w.write_utf("hello").unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { .. }));
    }

    #[test]
    fn writer_into_bytes_returns_full_buffer() {
        let w = BufWriter::new();
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), REQUEST_FRAME_SIZE);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn writer_as_bytes_returns_full_buffer_ref() {
        let w = BufWriter::new();
        assert_eq!(w.as_bytes().len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn writer_default_trait() {
        let w = BufWriter::default();
        assert_eq!(w.as_bytes().len(), REQUEST_FRAME_SIZE);
        assert_eq!(w.offset(), 0);
    }

    #[test]
    fn roundtrip_u8() {
        let mut w = BufWriter::new();
        w.write_u8(0xAB).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_u8().unwrap(), 0xAB);
    }

    #[test]
    fn roundtrip_bool() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        w.write_bool(false).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert!(r.read_bool().unwrap());
        assert!(!r.read_bool().unwrap());
    }

    #[test]
    fn roundtrip_i16() {
        let mut w = BufWriter::new();
        w.write_i16(-12345).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_i16().unwrap(), -12345);
    }

    #[test]
    fn roundtrip_u16() {
        let mut w = BufWriter::new();
        w.write_u16(54321).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_u16().unwrap(), 54321);
    }

    #[test]
    fn roundtrip_i32() {
        let mut w = BufWriter::new();
        w.write_i32(-123456789).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_i32().unwrap(), -123456789);
    }

    #[test]
    fn roundtrip_u32() {
        let mut w = BufWriter::new();
        w.write_u32(0xDEADBEEF).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_u32().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn roundtrip_utf16be_ascii() {
        let mut w = BufWriter::new();
        w.write_utf16be("hello world").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_utf16be().unwrap(), "hello world");
    }

    #[test]
    fn roundtrip_utf16be_korean() {
        let mut w = BufWriter::new();
        w.write_utf16be("강의계획서").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_utf16be().unwrap(), "강의계획서");
    }

    #[test]
    fn roundtrip_utf16be_mixed() {
        let mut w = BufWriter::new();
        w.write_utf16be("Hello 세계! 🌍").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_utf16be().unwrap(), "Hello 세계! 🌍");
    }

    #[test]
    fn roundtrip_utf16be_empty() {
        let mut w = BufWriter::new();
        w.write_utf16be("").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_utf16be().unwrap(), "");
    }

    #[test]
    fn roundtrip_utf_basic() {
        let mut w = BufWriter::new();
        w.write_utf("OZBINDEDDATAMODULE").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_utf().unwrap(), "OZBINDEDDATAMODULE");
    }

    #[test]
    fn roundtrip_utf_korean() {
        let mut w = BufWriter::new();
        w.write_utf("강의계획서").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_utf().unwrap(), "강의계획서");
    }

    #[test]
    fn roundtrip_utf_with_null() {
        let mut w = BufWriter::new();
        w.write_utf("A\0B").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_utf().unwrap(), "A\0B");
    }

    #[test]
    fn decode_modified_utf8_standard() {
        let bytes = b"hello";
        assert_eq!(decode_modified_utf8(bytes).unwrap(), "hello");
    }

    #[test]
    fn decode_modified_utf8_null_conversion() {
        // 0xC0 0x80 → 0x00
        let bytes = [0x41, 0xC0, 0x80, 0x42]; // "A\0B"
        let result = decode_modified_utf8(&bytes).unwrap();
        assert_eq!(result, "A\0B");
        assert_eq!(result.as_bytes(), &[0x41, 0x00, 0x42]);
    }

    #[test]
    fn decode_modified_utf8_multiple_nulls() {
        // 여러 null 문자: "\0\0"
        let bytes = [0xC0, 0x80, 0xC0, 0x80];
        let result = decode_modified_utf8(&bytes).unwrap();
        assert_eq!(result, "\0\0");
    }

    #[test]
    fn decode_modified_utf8_only_null() {
        let bytes = [0xC0, 0x80];
        let result = decode_modified_utf8(&bytes).unwrap();
        assert_eq!(result, "\0");
    }

    #[test]
    fn decode_modified_utf8_korean() {
        let s = "강의계획서";
        let result = decode_modified_utf8(s.as_bytes()).unwrap();
        assert_eq!(result, s);
    }

    #[test]
    fn decode_modified_utf8_empty() {
        let result = decode_modified_utf8(&[]).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn roundtrip_multiple_types_sequential() {
        let mut w = BufWriter::new();
        w.write_u32(crate::constants::MAGIC).unwrap();
        w.write_utf16be("TestClass").unwrap();
        w.write_u32(2).unwrap(); // field count
        w.write_utf16be("key1").unwrap();
        w.write_utf16be("value1").unwrap();
        w.write_utf16be("key2").unwrap();
        w.write_utf16be("value2").unwrap();
        w.write_bool(true).unwrap();
        w.write_i32(-42).unwrap();

        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_u32().unwrap(), crate::constants::MAGIC);
        assert_eq!(r.read_utf16be().unwrap(), "TestClass");
        assert_eq!(r.read_u32().unwrap(), 2);
        assert_eq!(r.read_utf16be().unwrap(), "key1");
        assert_eq!(r.read_utf16be().unwrap(), "value1");
        assert_eq!(r.read_utf16be().unwrap(), "key2");
        assert_eq!(r.read_utf16be().unwrap(), "value2");
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_i32().unwrap(), -42);
    }

    #[test]
    fn read_utf16be_surrogate_pair() {
        // 🌍 (U+1F30D) → UTF-16 서로게이트 페어: D83C DF0D (2 code units)
        let mut buf = Vec::new();
        let s = "🌍";
        let u16_units: Vec<u16> = s.encode_utf16().collect();
        assert_eq!(u16_units.len(), 2); // 서로게이트 페어
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for ch in &u16_units {
            buf.extend_from_slice(&ch.to_be_bytes());
        }
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf16be().unwrap(), "🌍");
    }

    #[test]
    fn read_utf16be_truncated_data_eof() {
        // charCount = 3이지만 2문자 분량만 제공 → UnexpectedEof
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes()); // charCount = 3
        buf.extend_from_slice(&0x0041u16.to_be_bytes()); // 'A'
        buf.extend_from_slice(&0x0042u16.to_be_bytes()); // 'B'
        // 3번째 문자 없음
        let mut r = BufReader::new(&buf);
        let err = r.read_utf16be().unwrap_err();
        assert!(matches!(err, OzError::UnexpectedEof { .. }));
    }

    #[test]
    fn read_utf_truncated_data_eof() {
        // byteLen = 10이지만 5바이트만 제공 → UnexpectedEof
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u16.to_be_bytes()); // byteLen = 10
        buf.extend_from_slice(b"hello"); // 5바이트만
        let mut r = BufReader::new(&buf);
        let err = r.read_utf().unwrap_err();
        assert!(matches!(err, OzError::UnexpectedEof { .. }));
    }

    #[test]
    fn read_bytes_zero_length() {
        let data = [0x01, 0x02];
        let mut r = BufReader::new(&data);
        let slice = r.read_bytes(0).unwrap();
        assert_eq!(slice.len(), 0);
        assert_eq!(r.offset(), 0); // 오프셋 변경 없음
    }

    #[test]
    fn set_offset_clamp_to_buf_len() {
        let data = [0x01, 0x02, 0x03];
        let mut r = BufReader::new(&data);
        r.set_offset(100); // 버퍼 길이(3)보다 큼
        assert_eq!(r.offset(), 3); // 클램핑
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn write_bytes_basic() {
        let mut w = BufWriter::new();
        w.write_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(&w.as_bytes()[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(w.offset(), 4);
    }

    #[test]
    fn write_bytes_empty() {
        let mut w = BufWriter::new();
        w.write_bytes(&[]).unwrap();
        assert_eq!(w.offset(), 0);
    }

    #[test]
    fn roundtrip_i64() {
        let mut w = BufWriter::new();
        w.write_i64(-9876543210).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_i64().unwrap(), -9876543210);
    }

    #[test]
    fn roundtrip_f32() {
        let mut w = BufWriter::new();
        w.write_f32(std::f32::consts::PI).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        let v = r.read_f32().unwrap();
        assert!((v - std::f32::consts::PI).abs() < f32::EPSILON);
    }

    #[test]
    fn roundtrip_f64() {
        let mut w = BufWriter::new();
        w.write_f64(std::f64::consts::E).unwrap();
        let mut r = BufReader::new(w.as_bytes());
        let v = r.read_f64().unwrap();
        assert!((v - std::f64::consts::E).abs() < f64::EPSILON);
    }

    #[test]
    fn write_i64_overflow() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 4; // 4 bytes left, need 8
        let err = w.write_i64(0).unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { needed: 8, .. }));
    }

    #[test]
    fn write_f32_overflow() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 2; // 2 bytes left, need 4
        let err = w.write_f32(0.0).unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { needed: 4, .. }));
    }

    #[test]
    fn write_f64_overflow() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 4; // 4 bytes left, need 8
        let err = w.write_f64(0.0).unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { needed: 8, .. }));
    }

    #[test]
    fn write_bytes_overflow() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 2;
        let err = w.write_bytes(&[0x00; 5]).unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { .. }));
    }
}

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
//!   null 문자가 `0xC0 0x80`으로, 보충 문자(U+10000 이상)가 surrogate pair로 인코딩됩니다.

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

    /// 1바이트 부호 있는 정수를 읽습니다.
    ///
    /// TinyInt(`SqlType`) 등 signed byte 값 읽기에 사용됩니다.
    pub fn read_i8(&mut self) -> Result<i8> {
        self.ensure(1)?;
        let v = self.buf[self.offset] as i8;
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

    /// 8바이트 Big Endian 부호 없는 정수를 읽습니다.
    ///
    /// 대용량 바이너리 크기 읽기 등에 사용됩니다.
    /// `ensure()`로 길이를 보장하므로 `try_into().unwrap()`은 안전합니다.
    pub fn read_u64(&mut self) -> Result<u64> {
        self.ensure(8)?;
        let v = u64::from_be_bytes(self.buf[self.offset..self.offset + 8].try_into().unwrap());
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
    /// Java Modified UTF-8에서 null 문자(`\0`)는 `0xC0 0x80`으로,
    /// 보충 문자(U+10000 이상)는 surrogate pair로 인코딩됩니다.
    pub fn read_utf(&mut self) -> Result<String> {
        let byte_len = self.read_u16()? as usize;
        let bytes = self.read_bytes(byte_len)?;
        decode_modified_utf8(bytes)
    }

    /// OZ 확장 Modified UTF-8 문자열을 읽습니다.
    ///
    /// 형식: `[4B byteLength (i32)] + [byteLength × 1B Modified UTF-8]`
    ///
    /// 일반 [`read_utf()`](Self::read_utf)가 2바이트(u16) 길이 prefix를 사용하는 반면,
    /// 이 메서드는 **4바이트(i32) 길이 prefix**를 사용합니다. 65,535 바이트를 초과하는
    /// 긴 문자열을 처리할 때 사용됩니다.
    ///
    /// 음수 길이가 읽히면 [`OzError::ProtocolError`]를 반환합니다.
    pub fn read_oz_utf(&mut self) -> Result<String> {
        let raw_len = self.read_i32()?;
        if raw_len < 0 {
            return Err(OzError::ProtocolError {
                code: 0,
                message: format!("negative oz_utf length: {}", raw_len),
            });
        }
        let byte_len = raw_len as usize;
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

    /// 1바이트 부호 있는 정수를 씁니다.
    ///
    /// Transaction 파라미터 직렬화 등에 사용됩니다.
    pub fn write_i8(&mut self, v: i8) -> Result<()> {
        self.ensure(1)?;
        self.buf[self.offset] = v as u8;
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

    /// 8바이트 Big Endian 부호 있는 정수를 씁니다.
    pub fn write_i64(&mut self, v: i64) -> Result<()> {
        self.ensure(8)?;
        let bytes = v.to_be_bytes();
        self.buf[self.offset..self.offset + 8].copy_from_slice(&bytes);
        self.offset += 8;
        Ok(())
    }

    /// 8바이트 Big Endian 부호 없는 정수를 씁니다.
    pub fn write_u64(&mut self, v: u64) -> Result<()> {
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
    /// 형식: `[2B byteLength] + [byteLength × 1B Modified UTF-8]`
    ///
    /// `cesu8::to_java_cesu8()`를 사용하여 null 문자(`\0`)를 `0xC0 0x80`으로,
    /// 보충 문자(U+10000 이상)를 surrogate pair로 인코딩합니다.
    pub fn write_utf(&mut self, s: &str) -> Result<()> {
        let cesu8_bytes = cesu8::to_java_cesu8(s);
        let byte_len = cesu8_bytes.len();
        let total_needed = 2 + byte_len;
        self.ensure(total_needed)?;

        // byteLength 기록 (2B)
        let len_bytes = (byte_len as u16).to_be_bytes();
        self.buf[self.offset..self.offset + 2].copy_from_slice(&len_bytes);
        self.offset += 2;

        // Modified UTF-8 바이트 기록
        self.buf[self.offset..self.offset + byte_len].copy_from_slice(&cesu8_bytes);
        self.offset += byte_len;
        Ok(())
    }

    /// OZ 확장 Modified UTF-8 문자열을 씁니다.
    ///
    /// 형식: `[4B byteLength (i32)] + [byteLength × 1B Modified UTF-8]`
    ///
    /// 일반 [`write_utf()`](Self::write_utf)가 2바이트(u16) 길이 prefix를 사용하는 반면,
    /// 이 메서드는 **4바이트(i32) 길이 prefix**를 사용합니다. 65,535 바이트를 초과하는
    /// 긴 문자열을 처리할 때 사용됩니다.
    ///
    /// `cesu8::to_java_cesu8()`를 사용하여 null 문자(`\0`)를 `0xC0 0x80`으로,
    /// 보충 문자(U+10000 이상)를 surrogate pair로 인코딩합니다.
    pub fn write_oz_utf(&mut self, s: &str) -> Result<()> {
        let cesu8_bytes = cesu8::to_java_cesu8(s);
        let byte_len = cesu8_bytes.len();
        let total_needed = 4 + byte_len;
        self.ensure(total_needed)?;

        // byteLength 기록 (4B, i32)
        let len_bytes = (byte_len as i32).to_be_bytes();
        self.buf[self.offset..self.offset + 4].copy_from_slice(&len_bytes);
        self.offset += 4;

        // Modified UTF-8 바이트 기록
        self.buf[self.offset..self.offset + byte_len].copy_from_slice(&cesu8_bytes);
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

    // ── 테스트 매크로 ──

    /// 기본 roundtrip 테스트: write -> read -> assert_eq
    macro_rules! roundtrip_test {
        ($name:ident, $write_fn:ident, $read_fn:ident, $value:expr) => {
            #[test]
            fn $name() {
                let mut w = BufWriter::new();
                w.$write_fn($value).unwrap();
                let mut r = BufReader::new(w.as_bytes());
                assert_eq!(r.$read_fn().unwrap(), $value);
            }
        };
    }

    /// 여러 값을 순차적으로 roundtrip 테스트
    macro_rules! roundtrip_multi_test {
        ($name:ident, $write_fn:ident, $read_fn:ident, $($value:expr),+ $(,)?) => {
            #[test]
            fn $name() {
                let mut w = BufWriter::new();
                $(w.$write_fn($value).unwrap();)+
                let mut r = BufReader::new(w.as_bytes());
                $(assert_eq!(r.$read_fn().unwrap(), $value);)+
            }
        };
    }

    /// 부동소수점 roundtrip 테스트: write -> read -> assert (v - expected).abs() < epsilon
    macro_rules! roundtrip_float_test {
        ($name:ident, $write_fn:ident, $read_fn:ident, $value:expr, $epsilon:expr) => {
            #[test]
            fn $name() {
                let mut w = BufWriter::new();
                w.$write_fn($value).unwrap();
                let mut r = BufReader::new(w.as_bytes());
                let v = r.$read_fn().unwrap();
                assert!((v - $value).abs() < $epsilon);
            }
        };
    }

    /// 버퍼 오버플로우 테스트: 버퍼 끝 근처에서 쓰기 시도 -> BufferOverflow
    macro_rules! overflow_test {
        ($name:ident, $write_fn:ident, $remaining:expr, $value:expr, $needed:expr) => {
            #[test]
            fn $name() {
                let mut w = BufWriter::new();
                w.offset = REQUEST_FRAME_SIZE - $remaining;
                let err = w.$write_fn($value).unwrap_err();
                assert!(matches!(
                    err,
                    OzError::BufferOverflow {
                        needed: $needed,
                        ..
                    }
                ));
            }
        };
    }

    /// EOF 테스트: 불충분한 바이트에서 읽기 시도 -> UnexpectedEof
    macro_rules! eof_test {
        ($name:ident, $read_fn:ident, $available:expr, $needed:expr) => {
            #[test]
            fn $name() {
                let data = [0u8; $available];
                let mut r = BufReader::new(&data);
                let err = r.$read_fn().unwrap_err();
                assert!(matches!(
                    err,
                    OzError::UnexpectedEof {
                        offset: 0,
                        needed: $needed,
                        available: $available
                    }
                ));
            }
        };
    }

    // ── 기본 read 테스트 ──

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
        assert!(r.read_bool().unwrap()); // 0xFF != 0 -> true
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

    // ── UTF-16BE read 테스트 ──

    #[test]
    fn read_utf16be_ascii() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        for ch in "guest".encode_utf16() {
            buf.extend_from_slice(&ch.to_be_bytes());
        }
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf16be().unwrap(), "guest");
    }

    #[test]
    fn read_utf16be_korean() {
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
        let buf = 0u32.to_be_bytes();
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf16be().unwrap(), "");
    }

    #[test]
    fn utf16be_length_is_char_count_not_byte_count() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&0x0041u16.to_be_bytes());
        buf.extend_from_slice(&0x0042u16.to_be_bytes());
        let mut r = BufReader::new(&buf);
        let s = r.read_utf16be().unwrap();
        assert_eq!(s, "AB");
        assert_eq!(r.offset(), 8);
    }

    // ── Modified UTF-8 read 테스트 ──

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
        let buf = [0x00, 0x00];
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf().unwrap(), "");
    }

    #[test]
    fn read_utf_null_char_modified_utf8() {
        let mut buf = Vec::new();
        let payload = [0x41, 0xC0, 0x80, 0x42]; // "A\0B"
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&payload);
        let mut r = BufReader::new(&buf);
        let result = r.read_utf().unwrap();
        assert_eq!(result, "A\0B");
        assert_eq!(result.len(), 3);
    }

    // ── EOF 테스트 (매크로 사용) ──

    eof_test!(read_u8_eof, read_u8, 0, 1);
    eof_test!(read_i8_eof, read_i8, 0, 1);
    eof_test!(read_u32_insufficient_bytes, read_u32, 2, 4);
    eof_test!(read_i64_eof_after_partial, read_i64, 4, 8);
    eof_test!(read_u64_eof, read_u64, 4, 8);

    // ── 오프셋 및 기타 리더 테스트 ──

    #[test]
    fn reader_offset_advances_correctly() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x12u8.to_be_bytes());
        buf.extend_from_slice(&0x1234u16.to_be_bytes());
        buf.extend_from_slice(&0x12345678u32.to_be_bytes());
        buf.extend_from_slice(&42i64.to_be_bytes());

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
    fn set_offset_clamp_to_buf_len() {
        let data = [0x01, 0x02, 0x03];
        let mut r = BufReader::new(&data);
        r.set_offset(100);
        assert_eq!(r.offset(), 3);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn read_bytes_zero_length() {
        let data = [0x01, 0x02];
        let mut r = BufReader::new(&data);
        let slice = r.read_bytes(0).unwrap();
        assert_eq!(slice.len(), 0);
        assert_eq!(r.offset(), 0);
    }

    // ── 기본 write 테스트 ──

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

    // ── UTF-16BE write 테스트 ──

    #[test]
    fn write_utf16be_ascii() {
        let mut w = BufWriter::new();
        w.write_utf16be("guest").unwrap();
        assert_eq!(&w.as_bytes()[..4], &5u32.to_be_bytes());
        assert_eq!(&w.as_bytes()[4..6], &[0x00, 0x67]);
        assert_eq!(w.offset(), 4 + 5 * 2);
    }

    #[test]
    fn write_utf16be_korean() {
        let mut w = BufWriter::new();
        w.write_utf16be("강의계획서").unwrap();
        assert_eq!(&w.as_bytes()[..4], &5u32.to_be_bytes());
        assert_eq!(w.offset(), 4 + 5 * 2);
    }

    #[test]
    fn write_utf16be_empty() {
        let mut w = BufWriter::new();
        w.write_utf16be("").unwrap();
        assert_eq!(&w.as_bytes()[..4], &0u32.to_be_bytes());
        assert_eq!(w.offset(), 4);
    }

    // ── Modified UTF-8 write 테스트 ──

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
        // "A\0B" -> 0x41, 0xC0, 0x80, 0x42 (4 bytes in Modified UTF-8)
        assert_eq!(&w.as_bytes()[..2], &4u16.to_be_bytes());
        assert_eq!(&w.as_bytes()[2..6], &[0x41, 0xC0, 0x80, 0x42]);
        assert_eq!(w.offset(), 6);
    }

    // ── write_bytes 테스트 ──

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

    // ── 오버플로우 테스트 (매크로 사용) ──

    overflow_test!(writer_overflow_u8, write_u8, 0, 0x00, 1);
    overflow_test!(writer_overflow_u32, write_u32, 2, 0u32, 4);
    overflow_test!(writer_overflow_i8, write_i8, 0, 0i8, 1);
    overflow_test!(writer_overflow_i64, write_i64, 4, 0i64, 8);
    overflow_test!(writer_overflow_u64, write_u64, 4, 0u64, 8);
    overflow_test!(writer_overflow_f32, write_f32, 2, 0.0f32, 4);
    overflow_test!(writer_overflow_f64, write_f64, 4, 0.0f64, 8);

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
    fn writer_overflow_bytes() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 2;
        let err = w.write_bytes(&[0x00; 5]).unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { .. }));
    }

    // ── 버퍼 유틸리티 테스트 ──

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

    // ── roundtrip 테스트 (매크로 사용) ──

    roundtrip_test!(roundtrip_u8, write_u8, read_u8, 0xAB);
    roundtrip_test!(roundtrip_i16, write_i16, read_i16, -12345i16);
    roundtrip_test!(roundtrip_u16, write_u16, read_u16, 54321u16);
    roundtrip_test!(roundtrip_i32, write_i32, read_i32, -123456789i32);
    roundtrip_test!(roundtrip_u32, write_u32, read_u32, 0xDEADBEEFu32);
    roundtrip_test!(roundtrip_i64, write_i64, read_i64, -9876543210i64);
    roundtrip_test!(roundtrip_u64, write_u64, read_u64, 12345678901234u64);
    roundtrip_test!(roundtrip_u64_max, write_u64, read_u64, u64::MAX);
    roundtrip_test!(roundtrip_u64_zero, write_u64, read_u64, 0u64);

    roundtrip_multi_test!(roundtrip_bool, write_bool, read_bool, true, false);
    roundtrip_multi_test!(roundtrip_i8, write_i8, read_i8, -128i8, 0i8, 127i8);

    roundtrip_float_test!(
        roundtrip_f32,
        write_f32,
        read_f32,
        std::f32::consts::PI,
        f32::EPSILON
    );
    roundtrip_float_test!(
        roundtrip_f64,
        write_f64,
        read_f64,
        std::f64::consts::E,
        f64::EPSILON
    );

    // ── 문자열 roundtrip 테스트 ──

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
    fn roundtrip_utf_supplementary_char() {
        // 보충 문자 (U+10000 이상) roundtrip 테스트
        let mut w = BufWriter::new();
        w.write_utf("Hello 🌍🎉").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_utf().unwrap(), "Hello 🌍🎉");
    }

    // ── decode_modified_utf8 테스트 ──

    #[test]
    fn decode_modified_utf8_standard() {
        let bytes = b"hello";
        assert_eq!(decode_modified_utf8(bytes).unwrap(), "hello");
    }

    #[test]
    fn decode_modified_utf8_null_conversion() {
        let bytes = [0x41, 0xC0, 0x80, 0x42]; // "A\0B"
        let result = decode_modified_utf8(&bytes).unwrap();
        assert_eq!(result, "A\0B");
        assert_eq!(result.as_bytes(), &[0x41, 0x00, 0x42]);
    }

    #[test]
    fn decode_modified_utf8_multiple_nulls() {
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

    // ── read_u64 테스트 ──

    #[test]
    fn read_u64_basic() {
        let data = 12345678901234u64.to_be_bytes();
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_u64().unwrap(), 12345678901234);
    }

    #[test]
    fn read_u64_max() {
        let data = u64::MAX.to_be_bytes();
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_u64().unwrap(), u64::MAX);
    }

    #[test]
    fn read_u64_zero() {
        let data = 0u64.to_be_bytes();
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_u64().unwrap(), 0);
    }

    // ── read_i8 테스트 ──

    #[test]
    fn read_i8_positive() {
        let data = [0x42];
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_i8().unwrap(), 0x42);
        assert_eq!(r.offset(), 1);
    }

    #[test]
    fn read_i8_negative() {
        let data = [0xFF]; // -1 as i8
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_i8().unwrap(), -1);
    }

    #[test]
    fn read_i8_min_max() {
        let data = [0x80, 0x7F]; // i8::MIN, i8::MAX
        let mut r = BufReader::new(&data);
        assert_eq!(r.read_i8().unwrap(), i8::MIN);
        assert_eq!(r.read_i8().unwrap(), i8::MAX);
    }

    // ── write_i8 테스트 ──

    #[test]
    fn write_i8_positive() {
        let mut w = BufWriter::new();
        w.write_i8(42).unwrap();
        assert_eq!(w.as_bytes()[0], 42);
        assert_eq!(w.offset(), 1);
    }

    #[test]
    fn write_i8_negative() {
        let mut w = BufWriter::new();
        w.write_i8(-1).unwrap();
        assert_eq!(w.as_bytes()[0], 0xFF);
        assert_eq!(w.offset(), 1);
    }

    // ── write_oz_utf / read_oz_utf 테스트 ──

    #[test]
    fn write_oz_utf_basic() {
        let mut w = BufWriter::new();
        w.write_oz_utf("hello").unwrap();
        assert_eq!(&w.as_bytes()[..4], &5i32.to_be_bytes());
        assert_eq!(&w.as_bytes()[4..9], b"hello");
        assert_eq!(w.offset(), 9);
    }

    #[test]
    fn write_oz_utf_empty() {
        let mut w = BufWriter::new();
        w.write_oz_utf("").unwrap();
        assert_eq!(&w.as_bytes()[..4], &0i32.to_be_bytes());
        assert_eq!(w.offset(), 4);
    }

    #[test]
    fn write_oz_utf_korean() {
        let mut w = BufWriter::new();
        let s = "강의계획서";
        let byte_len = s.len(); // 15 bytes in UTF-8
        w.write_oz_utf(s).unwrap();
        assert_eq!(&w.as_bytes()[..4], &(byte_len as i32).to_be_bytes());
        assert_eq!(w.offset(), 4 + byte_len);
    }

    #[test]
    fn write_oz_utf_null_char_modified_utf8() {
        let mut w = BufWriter::new();
        w.write_oz_utf("A\0B").unwrap();
        assert_eq!(&w.as_bytes()[..4], &4i32.to_be_bytes());
        assert_eq!(&w.as_bytes()[4..8], &[0x41, 0xC0, 0x80, 0x42]);
        assert_eq!(w.offset(), 8);
    }

    #[test]
    fn write_oz_utf_overflow() {
        let mut w = BufWriter::new();
        w.offset = REQUEST_FRAME_SIZE - 3;
        let err = w.write_oz_utf("hello").unwrap_err();
        assert!(matches!(err, OzError::BufferOverflow { .. }));
    }

    #[test]
    fn read_oz_utf_basic() {
        let s = "hello";
        let mut buf = Vec::new();
        buf.extend_from_slice(&(s.len() as i32).to_be_bytes());
        buf.extend_from_slice(s.as_bytes());
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_oz_utf().unwrap(), "hello");
    }

    #[test]
    fn read_oz_utf_korean() {
        let s = "강의계획서";
        let bytes = s.as_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
        buf.extend_from_slice(bytes);
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_oz_utf().unwrap(), "강의계획서");
    }

    #[test]
    fn read_oz_utf_empty() {
        let buf = 0i32.to_be_bytes();
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_oz_utf().unwrap(), "");
    }

    #[test]
    fn read_oz_utf_null_char_modified_utf8() {
        let mut buf = Vec::new();
        let payload = [0x41, 0xC0, 0x80, 0x42]; // "A\0B"
        buf.extend_from_slice(&(payload.len() as i32).to_be_bytes());
        buf.extend_from_slice(&payload);
        let mut r = BufReader::new(&buf);
        let result = r.read_oz_utf().unwrap();
        assert_eq!(result, "A\0B");
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn read_oz_utf_negative_length() {
        let buf = (-1i32).to_be_bytes();
        let mut r = BufReader::new(&buf);
        let err = r.read_oz_utf().unwrap_err();
        assert!(matches!(err, OzError::ProtocolError { .. }));
    }

    #[test]
    fn read_oz_utf_truncated_data_eof() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10i32.to_be_bytes());
        buf.extend_from_slice(b"hello"); // 5바이트만
        let mut r = BufReader::new(&buf);
        let err = r.read_oz_utf().unwrap_err();
        assert!(matches!(err, OzError::UnexpectedEof { .. }));
    }

    // ── oz_utf roundtrip 테스트 ──

    #[test]
    fn roundtrip_oz_utf_basic() {
        let mut w = BufWriter::new();
        w.write_oz_utf("OZBINDEDDATAMODULE").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_oz_utf().unwrap(), "OZBINDEDDATAMODULE");
    }

    #[test]
    fn roundtrip_oz_utf_korean() {
        let mut w = BufWriter::new();
        w.write_oz_utf("강의계획서").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_oz_utf().unwrap(), "강의계획서");
    }

    #[test]
    fn roundtrip_oz_utf_with_null() {
        let mut w = BufWriter::new();
        w.write_oz_utf("A\0B").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_oz_utf().unwrap(), "A\0B");
    }

    #[test]
    fn roundtrip_oz_utf_supplementary_char() {
        // 보충 문자 (U+10000 이상) roundtrip 테스트
        let mut w = BufWriter::new();
        w.write_oz_utf("Hello 🌍🎉").unwrap();
        let mut r = BufReader::new(w.as_bytes());
        assert_eq!(r.read_oz_utf().unwrap(), "Hello 🌍🎉");
    }

    // ── prefix 크기 비교 테스트 ──

    #[test]
    fn oz_utf_uses_4byte_prefix_vs_utf_2byte_prefix() {
        let mut w1 = BufWriter::new();
        w1.write_utf("test").unwrap();
        assert_eq!(w1.offset(), 2 + 4); // 2B prefix + 4B data

        let mut w2 = BufWriter::new();
        w2.write_oz_utf("test").unwrap();
        assert_eq!(w2.offset(), 4 + 4); // 4B prefix + 4B data
    }

    // ── UTF-16BE 에지 케이스 ──

    #[test]
    fn read_utf16be_surrogate_pair() {
        let mut buf = Vec::new();
        let s = "🌍";
        let u16_units: Vec<u16> = s.encode_utf16().collect();
        assert_eq!(u16_units.len(), 2);
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for ch in &u16_units {
            buf.extend_from_slice(&ch.to_be_bytes());
        }
        let mut r = BufReader::new(&buf);
        assert_eq!(r.read_utf16be().unwrap(), "🌍");
    }

    #[test]
    fn read_utf16be_truncated_data_eof() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(&0x0041u16.to_be_bytes());
        buf.extend_from_slice(&0x0042u16.to_be_bytes());
        let mut r = BufReader::new(&buf);
        let err = r.read_utf16be().unwrap_err();
        assert!(matches!(err, OzError::UnexpectedEof { .. }));
    }

    #[test]
    fn read_utf_truncated_data_eof() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u16.to_be_bytes());
        buf.extend_from_slice(b"hello"); // 5바이트만
        let mut r = BufReader::new(&buf);
        let err = r.read_utf().unwrap_err();
        assert!(matches!(err, OzError::UnexpectedEof { .. }));
    }

    // ── 복합 순차 roundtrip 테스트 ──

    #[test]
    fn roundtrip_multiple_types_sequential() {
        let mut w = BufWriter::new();
        w.write_u32(crate::constants::MAGIC).unwrap();
        w.write_utf16be("TestClass").unwrap();
        w.write_u32(2).unwrap();
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
}

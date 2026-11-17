//! Formatting satoshi amounts for display.

/// 21 million BTC in satoshis: no valid amount exceeds it.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Room for any u64, "184467440737.09551615 BTC".
pub const AMOUNT_MAX: usize = 28;

pub struct Amount {
    len: u8,
    buf: [u8; AMOUNT_MAX],
}

impl Amount {
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
}

/// `sats` as BTC with trailing zeros dropped, e.g. "0.0015 BTC" or "2 BTC".
pub fn format_btc(sats: u64) -> Amount {
    let mut buf = [0u8; AMOUNT_MAX];
    let mut len = 0;
    let whole = sats / 100_000_000;
    let mut frac = sats % 100_000_000;

    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut w = whole;
    loop {
        digits[n] = b'0' + (w % 10) as u8;
        n += 1;
        w /= 10;
        if w == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        buf[len] = digits[i];
        len += 1;
    }
    if frac != 0 {
        let mut places = 8;
        while frac.is_multiple_of(10) {
            frac /= 10;
            places -= 1;
        }
        buf[len] = b'.';
        len += 1;
        for i in (0..places).rev() {
            buf[len + i] = b'0' + (frac % 10) as u8;
            frac /= 10;
        }
        len += places;
    }
    for &c in b" BTC" {
        buf[len] = c;
        len += 1;
    }
    Amount {
        len: len as u8,
        buf,
    }
}

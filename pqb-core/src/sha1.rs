//! SHA-1, for the menu commitments `m[i] = SHA1(g[i])` that the PQB script
//! checks with OP_SHA1. The inputs are menu signatures of at most 73 bytes, so
//! this only ever hashes one or two blocks. No data-dependent branches.

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64) * 8;
    let mut block = [0u8; 64];
    let mut i = 0;
    // Whole blocks, then the padded tail (one or two blocks).
    while data.len() - i >= 64 {
        block.copy_from_slice(&data[i..i + 64]);
        compress(&mut h, &block);
        i += 64;
    }
    let rest = data.len() - i;
    block = [0u8; 64];
    block[..rest].copy_from_slice(&data[i..]);
    block[rest] = 0x80;
    if rest >= 56 {
        compress(&mut h, &block);
        block = [0u8; 64];
    }
    block[56..].copy_from_slice(&bit_len.to_be_bytes());
    compress(&mut h, &block);
    block.fill(0);
    core::hint::black_box(&mut block);

    let mut out = [0u8; 20];
    for (k, word) in h.iter().enumerate() {
        out[4 * k..4 * k + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (t, &wt) in w.iter().enumerate() {
        let (f, k) = match t {
            0..=19 => ((b & c) | (!b & d), 0x5A827999),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let tmp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wt);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    w.fill(0);
    core::hint::black_box(&mut w);
}

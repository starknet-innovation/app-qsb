//! Builds the Nano home-screen glyph from the app icon: inside the rounded-square
//! mask the icon is inverted (black mark on white), outside it is black.
//! Adapted from LedgerHQ/app-boilerplate-rust.

use std::path::{Path, PathBuf};

/// Decode a GIF's first frame into an 8-bit grayscale (luma) buffer, row-major.
fn gif_to_luma(path: &Path) -> (u32, u32, Vec<u8>) {
    let file = std::fs::File::open(path).unwrap();
    let mut options = gif::DecodeOptions::new();
    options.set_color_output(gif::ColorOutput::RGBA);
    let mut reader = options.read_info(file).unwrap();

    let width = reader.width() as u32;
    let height = reader.height() as u32;
    let mut luma = vec![0u8; (width * height) as usize];

    if let Some(frame) = reader.read_next_frame().unwrap() {
        let fw = frame.width as u32;
        let fh = frame.height as u32;
        for fy in 0..fh {
            for fx in 0..fw {
                let i = ((fy * fw + fx) * 4) as usize;
                let r = frame.buffer[i] as u32;
                let g = frame.buffer[i + 1] as u32;
                let b = frame.buffer[i + 2] as u32;
                let v = ((2126 * r + 7152 * g + 722 * b) / 10000) as u8;
                let cx = frame.left as u32 + fx;
                let cy = frame.top as u32 + fy;
                luma[(cy * width + cx) as usize] = v;
            }
        }
    }
    (width, height, luma)
}

fn main() {
    println!("cargo:rerun-if-changed=icons/pqb_14x14.gif");
    println!("cargo:rerun-if-changed=icons/mask_14x14.gif");

    let icons = PathBuf::from("icons");
    let (width, height, mut gray) = gif_to_luma(&icons.join("pqb_14x14.gif"));
    let (mask_w, mask_h, mask) = gif_to_luma(&icons.join("mask_14x14.gif"));
    assert_eq!(
        (width, height),
        (mask_w, mask_h),
        "icon and mask dimensions must match"
    );

    for (pixel, &mask_value) in gray.iter_mut().zip(mask.iter()) {
        *pixel = if mask_value == 0 { 0 } else { 255 - *pixel };
    }

    let glyph_path = PathBuf::from("glyphs").join("home_nano_nbgl.png");
    let file = std::io::BufWriter::new(std::fs::File::create(glyph_path).unwrap());
    let mut encoder = png::Encoder::new(file, width, height);
    encoder.set_color(png::ColorType::Grayscale);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .unwrap()
        .write_image_data(&gray)
        .unwrap();
}

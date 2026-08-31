use qrcode::{Color, QrCode};
use slint::{Rgba8Pixel, SharedPixelBuffer};

pub(crate) const PAYMENT_QR_IMAGE_SIZE: u32 = 220;
const QUIET_ZONE_MODULES: u32 = 4;
const LIGHT_PIXEL: [u8; 4] = [255, 255, 255, 255];
const DARK_PIXEL: [u8; 4] = [15, 35, 28, 255];

pub(crate) fn render_payment_url(
    payment_url: &str,
) -> Result<SharedPixelBuffer<Rgba8Pixel>, String> {
    let code = QrCode::new(payment_url.as_bytes())
        .map_err(|_| "支付链接内容过长，无法生成二维码。".to_owned())?;
    let module_width =
        u32::try_from(code.width()).map_err(|_| "支付二维码尺寸超出客户端支持范围。".to_owned())?;
    let total_modules = module_width + QUIET_ZONE_MODULES * 2;
    let module_scale = PAYMENT_QR_IMAGE_SIZE / total_modules;
    if module_scale == 0 {
        return Err("支付二维码尺寸超出客户端支持范围。".to_owned());
    }

    let rendered_size = total_modules * module_scale;
    let origin = (PAYMENT_QR_IMAGE_SIZE - rendered_size) / 2 + QUIET_ZONE_MODULES * module_scale;
    let colors = code.to_colors();
    let mut buffer =
        SharedPixelBuffer::<Rgba8Pixel>::new(PAYMENT_QR_IMAGE_SIZE, PAYMENT_QR_IMAGE_SIZE);
    let bytes = buffer.make_mut_bytes();
    for pixel in bytes.chunks_exact_mut(4) {
        pixel.copy_from_slice(&LIGHT_PIXEL);
    }

    for module_y in 0..module_width {
        for module_x in 0..module_width {
            let module_index = (module_y * module_width + module_x) as usize;
            if colors[module_index] != Color::Dark {
                continue;
            }
            let pixel_x = origin + module_x * module_scale;
            let pixel_y = origin + module_y * module_scale;
            for y in pixel_y..pixel_y + module_scale {
                for x in pixel_x..pixel_x + module_scale {
                    let pixel_index = ((y * PAYMENT_QR_IMAGE_SIZE + x) * 4) as usize;
                    bytes[pixel_index..pixel_index + 4].copy_from_slice(&DARK_PIXEL);
                }
            }
        }
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::{DARK_PIXEL, LIGHT_PIXEL, PAYMENT_QR_IMAGE_SIZE, render_payment_url};

    #[test]
    fn payment_url_renders_to_fixed_high_contrast_image() {
        let buffer = render_payment_url("https://pay.example.test/order/TN202608230001")
            .expect("normal payment URL should render");

        assert_eq!(buffer.width(), PAYMENT_QR_IMAGE_SIZE);
        assert_eq!(buffer.height(), PAYMENT_QR_IMAGE_SIZE);
        assert_eq!(&buffer.as_bytes()[..4], &LIGHT_PIXEL);
        assert!(
            buffer
                .as_bytes()
                .chunks_exact(4)
                .any(|pixel| pixel == DARK_PIXEL)
        );
    }

    #[test]
    fn oversized_payment_payload_returns_a_customer_safe_error() {
        let error = render_payment_url(&"x".repeat(5_000))
            .expect_err("oversized payment payload should be rejected");

        assert_eq!(error, "支付链接内容过长，无法生成二维码。");
    }
}

//! Shared formatting utilities used by both `mib_support` and `cli::output`.

/// Format TimeTicks (centiseconds) as a human-readable duration string.
///
/// Output format: `Xd HH:MM:SS.CC` (with days) or `HH:MM:SS.CC` (without).
#[cfg(any(feature = "cli", feature = "mib"))]
pub(crate) fn format_timeticks(centiseconds: u32) -> String {
    let total_seconds = centiseconds / 100;
    let cs = centiseconds % 100;

    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if days > 0 {
        format!(
            "{}d {:02}:{:02}:{:02}.{:02}",
            days, hours, minutes, seconds, cs
        )
    } else {
        format!("{:02}:{:02}:{:02}.{:02}", hours, minutes, seconds, cs)
    }
}

/// Format bytes as space-separated uppercase hex (e.g., "0A 1B 2C").
#[cfg(any(feature = "cli", feature = "mib"))]
pub(crate) fn format_hex_display(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(all(test, any(feature = "cli", feature = "mib")))]
mod tests {
    use super::*;

    #[test]
    fn test_format_timeticks() {
        assert_eq!(format_timeticks(12345678), "1d 10:17:36.78");
        assert_eq!(format_timeticks(360000), "01:00:00.00");
        assert_eq!(format_timeticks(0), "00:00:00.00");
    }

    #[test]
    fn test_format_hex_display() {
        assert_eq!(format_hex_display(&[0x00, 0x1A, 0x2B]), "00 1A 2B");
        assert_eq!(format_hex_display(&[]), "");
    }
}

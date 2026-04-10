# Media Sanitization

The `media` package provides media type detection, structural validation, and metadata stripping for media files in the Signal protocol. The implementation is intentionally minimal: JPEG and PNG files have metadata stripped, while MP4, WebP, and GIF files are structurally validated and returned unmodified.

## Supported Formats

| Format | Detection | Sanitization | MetadataStripped |
|--------|-----------|--------------|------------------|
| JPEG | `0xFF 0xD8 0xFF` at offset 0 | Strips APP1 (EXIF/XMP), APP2 (ICC), APP13 (IPTC), COM markers | `true` |
| PNG | 8-byte PNG signature at offset 0 | Strips tEXt, zTXt, iTXt, eXIf, iCCP, tIME chunks | `true` |
| MP4 | `ftyp` at offset 4 (ISO BMFF) | Structural validation only | `false` |
| WebP | `RIFF` at offset 0, `WEBP` at offset 8 | Structural validation only | `false` |
| GIF | `GIF87a` or `GIF89a` at offset 0 | Structural validation only | `false` |

## SanitizeResult

`Sanitize` returns a `*SanitizeResult` on success:

```go
type SanitizeResult struct {
    MediaType        MediaType  // detected format
    Sanitized        []byte     // output data
    OriginalSize     int64      // input size in bytes
    MetadataStripped bool       // true if metadata was actually removed
}
```

The `MetadataStripped` field distinguishes between formats where the sanitizer actively removes metadata (`true` for JPEG and PNG) and formats where only structural validation is performed (`false` for MP4, WebP, and GIF). When `MetadataStripped` is `false`, the `Sanitized` field contains a copy of the original input data.

## Usage

```go
result, err := media.Sanitize(data)
if err != nil {
    // handle error (unsupported format, invalid structure, etc.)
}

fmt.Println(result.MediaType)        // e.g. "JPEG"
fmt.Println(result.MetadataStripped) // true for JPEG/PNG, false for others
output := result.Sanitized           // clean data
```

For streaming input, use `SanitizeReader`:

```go
result, err := media.SanitizeReader(file)
```

`SanitizeReader` reads all data into memory before sanitizing. Callers should enforce size limits before calling it.

## Type Detection

`DetectMediaType` identifies the format from magic bytes. It requires at least 12 bytes for full detection (the WebP signature spans offsets 0-11), but can detect JPEG (3 bytes), GIF (6 bytes), and PNG (8 bytes) from shorter inputs. Returns `MediaTypeUnknown` if no format matches.

Each `MediaType` value exposes `String()` (e.g., `"JPEG"`) and `MIMEType()` (e.g., `"image/jpeg"`).

## JPEG Stripping

The JPEG sanitizer walks the marker structure after the SOI (Start of Image) marker. It copies all markers except:

- `0xE1` (APP1): EXIF data, XMP metadata
- `0xE2` (APP2): ICC color profiles
- `0xED` (APP13): IPTC/Photoshop metadata
- `0xFE` (COM): comment fields

When the SOS (Start of Scan) marker is reached, the sanitizer copies it and all remaining data verbatim, since scan data is not structured with length-prefixed markers.

## PNG Stripping

The PNG sanitizer walks the chunk structure after the 8-byte PNG signature. It copies all chunks except:

- `tEXt`, `zTXt`, `iTXt`: text metadata
- `eXIf`: EXIF data
- `iCCP`: ICC color profiles
- `tIME`: last modification time

Critical chunks (`IHDR`, `PLTE`, `IDAT`, `IEND`) and other safe ancillary chunks are preserved.

## Structural Validation (MP4, WebP, GIF)

For MP4, WebP, and GIF, the sanitizer performs structural validation without modifying the data. This catches obviously malformed files but does not strip embedded metadata.

**MP4** (`ValidateMP4`): Verifies the `ftyp` box is present at the start, then walks the top-level ISO BMFF box structure checking that each box's size/type header is well-formed and does not extend beyond the file. Handles both standard 32-bit box sizes and 64-bit extended sizes (`boxSize == 1`). A box size of 0 means the box extends to end of file, per the ISO BMFF specification.

**WebP** (`ValidateWebP`): Checks for the `RIFF` header at offset 0 and `WEBP` signature at offset 8. Verifies that the declared RIFF chunk size does not exceed the actual data length.

**GIF** (`ValidateGIF`): Checks for a valid GIF header (`GIF87a` or `GIF89a`) and verifies the file is long enough to contain the Logical Screen Descriptor (minimum 13 bytes).

## Errors

| Error | When |
|-------|------|
| `ErrUnsupportedMediaType` | Format could not be detected |
| `ErrDataTooShort` | Input is less than 3 bytes |
| `ErrInvalidMP4` | MP4 structural validation failed |
| `ErrInvalidWebP` | WebP structural validation failed |
| `ErrInvalidJPEG` | JPEG structural validation failed |
| `ErrInvalidPNG` | PNG structural validation failed |
| `ErrInvalidGIF` | GIF structural validation failed |

Detailed structural errors are returned as `*MediaValidationError` with a `Detail` string describing the specific failure (e.g., "MP4 truncated box header", "JPEG marker extends beyond data").

## Design Decisions

The package performs structural validation rather than deep metadata stripping for MP4, WebP, and GIF. Full sanitization for these formats would require substantial format-specific parsing (ISO BMFF atom trees for MP4, VP8/VP8L/VP8X chunk handling for WebP, extension block parsing for GIF). Production deployments that need thorough metadata removal for these formats should use specialized libraries.

## File

The full implementation is in `media/media.go`.

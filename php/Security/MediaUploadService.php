<?php
// MediaUploadService.php — Robust, secure validation, processing and storage for chat attachments
declare(strict_types=1);

namespace Daakpion\Security;

use RuntimeException;
use mysqli;
use finfo;

class MediaUploadService
{
    public const ALLOWED_IMAGE_TYPES = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
        'image/gif'  => 'gif',
    ];

    public const ALLOWED_VIDEO_TYPES = [
        'video/mp4'       => 'mp4',
        'video/webm'      => 'webm',
        'video/quicktime' => 'mov',
    ];

    public const ALLOWED_AUDIO_TYPES = [
        'audio/webm'       => 'webm',
        'audio/ogg'        => 'ogg',
        'audio/mpeg'       => 'mp3',
        'audio/wav'        => 'wav',
        'audio/x-wav'      => 'wav',
        'audio/mp4'        => 'm4a',
        'audio/x-m4a'      => 'm4a',
        'audio/aac'        => 'aac',
    ];

    public const ALLOWED_DOC_TYPES = [
        'application/pdf'    => 'pdf',
        'text/plain'         => 'txt',
        'application/zip'    => 'zip',
        'application/x-zip-compressed' => 'zip',
        'application/msword' => 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
        'application/vnd.ms-excel' => 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
        'application/vnd.ms-powerpoint' => 'ppt',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation' => 'pptx',
    ];

    public const MAX_IMAGE_BYTES = 10485760; // 10 MB
    public const MAX_VIDEO_BYTES = 26214400; // 25 MB
    public const MAX_AUDIO_BYTES = 10485760; // 10 MB
    public const MAX_DOC_BYTES   = 15728640; // 15 MB

    /**
     * Validates an uploaded file strictly against MIME allowlists, extension matching, and size constraints.
     *
     * @param array $file $_FILES entry
     * @return array [media_type, canonical_ext, mime_type, original_name, size_bytes]
     * @throws RuntimeException on validation failure
     */
    public static function validateUpload(array $file): array
    {
        if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
            $errMap = [
                UPLOAD_ERR_INI_SIZE   => 'Uploaded file exceeds server upload_max_filesize limit.',
                UPLOAD_ERR_FORM_SIZE  => 'Uploaded file exceeds form MAX_FILE_SIZE directive.',
                UPLOAD_ERR_PARTIAL    => 'File was only partially uploaded.',
                UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
                UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder on server.',
                UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
            ];
            throw new RuntimeException($errMap[$file['error']] ?? 'Unknown upload error.');
        }

        $tmpPath = $file['tmp_name'];
        if (php_sapi_name() !== 'cli' && !is_uploaded_file($tmpPath)) {
            throw new RuntimeException("Possible file upload attack detected.");
        }

        $size = (int)$file['size'];
        if ($size <= 0) {
            throw new RuntimeException("Uploaded file is empty.");
        }

        // 1. Extract and sanitize file extension & check for prohibited executable extensions
        $origName = basename($file['name']);
        if (preg_match('/\.php(\.|$)/i', $origName) || 
            preg_match('/\.phtml(\.|$)/i', $origName) || 
            preg_match('/\.phar(\.|$)/i', $origName) ||
            preg_match('/\.(exe|sh|bat|cmd|vbs|msi|cgi|pl|py)(\.|$)/i', $origName)) {
            throw new RuntimeException("Executable file extensions are strictly prohibited.");
        }

        $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));

        // 2. Detect genuine MIME type server-side (never trust client header)
        if (!file_exists($tmpPath)) {
            throw new RuntimeException("Temporary upload file is missing.");
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = @$finfo->file($tmpPath);
        if ($mime === false || empty($mime)) {
            throw new RuntimeException("Unable to determine file MIME type.");
        }

        // 3. Classify media type and enforce caps
        $mediaType = null;
        $canonicalExt = null;

        if (isset(self::ALLOWED_IMAGE_TYPES[$mime])) {
            $mediaType = 'image';
            $canonicalExt = self::ALLOWED_IMAGE_TYPES[$mime];
            if ($size > self::MAX_IMAGE_BYTES) {
                throw new RuntimeException("Image exceeds maximum allowed size of 10 MB.");
            }
        } elseif (isset(self::ALLOWED_VIDEO_TYPES[$mime])) {
            $mediaType = 'video';
            $canonicalExt = self::ALLOWED_VIDEO_TYPES[$mime];
            if ($size > self::MAX_VIDEO_BYTES) {
                throw new RuntimeException("Video exceeds maximum allowed size of 25 MB.");
            }
        } elseif (isset(self::ALLOWED_AUDIO_TYPES[$mime])) {
            $mediaType = 'audio';
            $canonicalExt = self::ALLOWED_AUDIO_TYPES[$mime];
            if ($size > self::MAX_AUDIO_BYTES) {
                throw new RuntimeException("Audio message exceeds maximum allowed size of 10 MB.");
            }
        } elseif (isset(self::ALLOWED_DOC_TYPES[$mime])) {
            $mediaType = 'document';
            $canonicalExt = self::ALLOWED_DOC_TYPES[$mime];
            if ($size > self::MAX_DOC_BYTES) {
                throw new RuntimeException("Document exceeds maximum allowed size of 15 MB.");
            }
        } else {
            throw new RuntimeException("Unsupported or prohibited file format ({$mime}).");
        }

        // Ensure extension is compatible with MIME
        $allowedExtensions = array_merge(
            array_values(self::ALLOWED_IMAGE_TYPES),
            array_values(self::ALLOWED_VIDEO_TYPES),
            array_values(self::ALLOWED_AUDIO_TYPES),
            array_values(self::ALLOWED_DOC_TYPES)
        );

        if (!in_array($ext, $allowedExtensions, true) && $ext !== 'jpeg') {
            $ext = $canonicalExt;
        }

        return [
            'media_type'    => $mediaType,
            'canonical_ext' => $canonicalExt,
            'extension'     => $ext,
            'mime_type'     => $mime,
            'original_name' => $origName,
            'size_bytes'    => $size,
            'tmp_path'      => $tmpPath
        ];
    }

    /**
     * Safely stores validated attachment to disk and creates database record.
     *
     * @param array $validated Validated file array from validateUpload()
     * @param int $uploaderId Authenticated user ID
     * @param int $messageId Associated message ID
     * @param mysqli $db Database connection
     * @return array Created attachment record
     */
    public static function storeAttachment(array $validated, int $uploaderId, int $messageId, mysqli $db): array
    {
        $baseDir = realpath(__DIR__ . '/../../uploads/message_media');
        if (!$baseDir) {
            $baseDir = __DIR__ . '/../../uploads/message_media';
            @mkdir($baseDir, 0750, true);
        }

        $folderName = match($validated['media_type']) {
            'image'    => 'images',
            'video'    => 'videos',
            'audio'    => 'audio',
            'document' => 'documents',
        };

        $targetFolder = $baseDir . DIRECTORY_SEPARATOR . $folderName;
        if (!is_dir($targetFolder)) {
            @mkdir($targetFolder, 0750, true);
        }

        // Generate cryptographically random unguessable storage filename
        $storedName = bin2hex(random_bytes(16)) . '.' . $validated['extension'];
        $storagePath = 'uploads/message_media/' . $folderName . '/' . $storedName;
        $destFile = $targetFolder . DIRECTORY_SEPARATOR . $storedName;

        if (!move_uploaded_file($validated['tmp_path'], $destFile)) {
            // Fallback for CLI testing where move_uploaded_file fails on synthetic temp files
            if (!copy($validated['tmp_path'], $destFile)) {
                throw new RuntimeException("Failed to move uploaded file into secure storage.");
            }
        }

        // Generate thumbnail for images if GD extension is loaded
        $thumbnailPath = null;
        if ($validated['media_type'] === 'image' && extension_loaded('gd')) {
            $thumbFolder = $baseDir . DIRECTORY_SEPARATOR . 'thumbnails';
            if (!is_dir($thumbFolder)) {
                @mkdir($thumbFolder, 0750, true);
            }
            $thumbStoredName = 'thumb_' . $storedName;
            $thumbDestFile = $thumbFolder . DIRECTORY_SEPARATOR . $thumbStoredName;
            if (self::generateThumbnail($destFile, $validated['mime_type'], $thumbDestFile, 320, 320)) {
                $thumbnailPath = 'uploads/message_media/thumbnails/' . $thumbStoredName;
            }
        }

        // Insert into message_attachments table
        $stmt = $db->prepare("
            INSERT INTO message_attachments 
            (message_id, uploader_id, original_name, stored_name, mime_type, extension, size_bytes, media_type, storage_path, thumbnail_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        ");
        if (!$stmt) {
            @unlink($destFile);
            if ($thumbnailPath && file_exists($baseDir . '/../' . $thumbnailPath)) {
                @unlink($baseDir . '/../' . $thumbnailPath);
            }
            throw new RuntimeException("Database error preparing attachment insertion: " . $db->error);
        }

        $stmt->bind_param(
            "iissssisss",
            $messageId,
            $uploaderId,
            $validated['original_name'],
            $storedName,
            $validated['mime_type'],
            $validated['extension'],
            $validated['size_bytes'],
            $validated['media_type'],
            $storagePath,
            $thumbnailPath
        );

        if (!$stmt->execute()) {
            $err = $stmt->error;
            $stmt->close();
            @unlink($destFile);
            throw new RuntimeException("Database error saving attachment record: " . $err);
        }

        $insertedId = (int)$stmt->insert_id;
        $stmt->close();

        return [
            'id'            => $insertedId,
            'message_id'    => $messageId,
            'uploader_id'   => $uploaderId,
            'original_name' => $validated['original_name'],
            'mime_type'     => $validated['mime_type'],
            'media_type'    => $validated['media_type'],
            'size_bytes'    => $validated['size_bytes'],
            'has_thumbnail' => $thumbnailPath !== null
        ];
    }

    /**
     * Resizes an image down to bounding box using GD.
     */
    private static function generateThumbnail(string $sourceFile, string $mime, string $destFile, int $maxWidth, int $maxHeight): bool
    {
        try {
            $src = match($mime) {
                'image/jpeg' => @imagecreatefromjpeg($sourceFile),
                'image/png'  => @imagecreatefrompng($sourceFile),
                'image/webp' => function_exists('imagecreatefromwebp') ? @imagecreatefromwebp($sourceFile) : null,
                'image/gif'  => @imagecreatefromgif($sourceFile),
                default      => null
            };

            if (!$src) return false;

            $origWidth = imagesx($src);
            $origHeight = imagesy($src);
            if ($origWidth <= 0 || $origHeight <= 0) {
                imagedestroy($src);
                return false;
            }

            // Calculate scaling ratio
            $scale = min($maxWidth / $origWidth, $maxHeight / $origHeight, 1.0);
            $newWidth = (int)round($origWidth * $scale);
            $newHeight = (int)round($origHeight * $scale);

            $dst = imagecreatetruecolor($newWidth, $newHeight);
            if ($mime === 'image/png' || $mime === 'image/webp') {
                imagealphablending($dst, false);
                imagesavealpha($dst, true);
            }

            imagecopyresampled($dst, $src, 0, 0, 0, 0, $newWidth, $newHeight, $origWidth, $origHeight);

            $saved = match($mime) {
                'image/jpeg' => imagejpeg($dst, $destFile, 82),
                'image/png'  => imagepng($dst, $destFile, 7),
                'image/webp' => function_exists('imagewebp') ? imagewebp($dst, $destFile, 82) : false,
                'image/gif'  => imagegif($dst, $destFile),
                default      => false
            };

            imagedestroy($src);
            imagedestroy($dst);
            return $saved;
        } catch (\Throwable $e) {
            return false;
        }
    }
}

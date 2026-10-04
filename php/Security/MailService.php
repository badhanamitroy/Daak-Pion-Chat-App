<?php
namespace Daakpion\Security;

use mysqli;
use Throwable;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

/**
 * MailService — Production-capable, hardened email delivery service.
 *
 * Responsibilities:
 * - Centralizes SMTP configuration and credential retrieval.
 * - Secure PHPMailer integration with strict TLS verification.
 * - Renders responsive HTML and plain-text fallback templates.
 * - Strict audit logging (zero leakage of OTPs, tokens, or credentials).
 * - Safe error handling preventing user enumeration or credential exposure.
 */
class MailService
{
    private ?mysqli $db;
    private AuditLogger $logger;
    private ?string $lastError = null;
    private ?string $templateDir = null;

    public function __construct(?mysqli $db = null, ?AuditLogger $logger = null)
    {
        $this->db = $db;
        $this->logger = $logger ?? new AuditLogger($db);
        $this->templateDir = __DIR__ . '/../../emails';
    }

    /**
     * Resolves SMTP configuration value from defined constants or environment variables.
     */
    private static function getConfig(string $key, $default = null)
    {
        if (defined($key)) {
            return constant($key);
        }

        $env = getenv($key);
        if ($env !== false && $env !== '') {
            return $env;
        }

        if (!empty($_ENV[$key])) {
            return $_ENV[$key];
        }

        if (!empty($_SERVER[$key])) {
            return $_SERVER[$key];
        }

        return $default;
    }

    /**
     * Checks if SMTP delivery has been configured with non-placeholder values.
     */
    public static function isConfigured(): bool
    {
        $host = (string)self::getConfig('SMTP_HOST', '');
        if ($host === '' || $host === 'REPLACE_WITH_SMTP_HOST') {
            return false;
        }

        $username = (string)self::getConfig('SMTP_USERNAME', '');
        if (str_starts_with($username, 'REPLACE_WITH_')) {
            return false;
        }

        return true;
    }

    /**
     * Resolves the canonical base application URL for links in emails.
     */
    public static function getAppBaseUrl(): string
    {
        $configured = self::getConfig('APP_URL');
        if (!empty($configured) && is_string($configured)) {
            return rtrim($configured, '/');
        }

        // Dynamic derivation fallback for local dev
        if (!empty($_SERVER['HTTP_HOST'])) {
            $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                    || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);
            $proto = $isHttps ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'];
            return "{$proto}://{$host}/Daakpion";
        }

        return 'http://localhost/Daakpion';
    }

    /**
     * Builds and configures a PHPMailer instance.
     *
     * @throws PHPMailerException
     */
    protected function createMailer(): PHPMailer
    {
        $mailer = new PHPMailer(true);

        $host       = (string)self::getConfig('SMTP_HOST', '127.0.0.1');
        $port       = (int)self::getConfig('SMTP_PORT', 587);
        $username   = (string)self::getConfig('SMTP_USERNAME', '');
        $password   = (string)self::getConfig('SMTP_PASSWORD', '');
        $encryption = strtolower((string)self::getConfig('SMTP_ENCRYPTION', 'tls'));
        $fromEmail  = (string)self::getConfig('MAIL_FROM_ADDRESS', 'noreply@daakpion.local');
        $fromName   = (string)self::getConfig('MAIL_FROM_NAME', 'DaakPion');

        $mailer->isSMTP();
        $mailer->Host       = $host;
        $mailer->Port       = $port;
        $mailer->Timeout    = 10;
        $mailer->CharSet    = PHPMailer::CHARSET_UTF8;

        if ($username !== '') {
            $mailer->SMTPAuth = true;
            $mailer->Username = $username;
            $mailer->Password = $password;
        } else {
            $mailer->SMTPAuth = false;
        }

        // Encryption settings
        if ($encryption === 'ssl' || $encryption === 'smtps') {
            $mailer->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        } elseif ($encryption === 'tls' || $encryption === 'starttls') {
            $mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        } else {
            $mailer->SMTPSecure = false;
            $mailer->SMTPAutoTLS = false;
        }

        // Strict TLS Certificate Verification (Defense in Depth)
        // Insecure verification is strictly forbidden by default
        $allowInsecure = defined('SMTP_ALLOW_INSECURE_DEV_CERTS') && constant('SMTP_ALLOW_INSECURE_DEV_CERTS') === true;
        if ($allowInsecure && Environment::isDevelopment()) {
            $mailer->SMTPOptions = [
                'ssl' => [
                    'verify_peer'       => false,
                    'verify_peer_name'  => false,
                    'allow_self_signed' => true,
                ],
            ];
        }

        $mailer->setFrom($fromEmail, $fromName);

        return $mailer;
    }

    /**
     * Sanitizes error message strings to ensure SMTP passwords or tokens are never exposed.
     */
    private function sanitizeErrorMessage(string $rawMessage): string
    {
        $smtpPass = (string)self::getConfig('SMTP_PASSWORD', '');
        if ($smtpPass !== '' && strlen($smtpPass) >= 3) {
            $rawMessage = str_replace($smtpPass, '[REDACTED]', $rawMessage);
        }
        $encKey = (string)self::getConfig('MESSAGE_ENCRYPTION_KEY', '');
        if ($encKey !== '' && strlen($encKey) >= 8) {
            $rawMessage = str_replace($encKey, '[REDACTED]', $rawMessage);
        }
        return preg_replace('/(password|pass|secret)=[^&\s]+/i', '$1=[REDACTED]', $rawMessage);
    }

    /**
     * Renders an email template file with variables replaced.
     */
    private function renderTemplate(string $filename, array $placeholders): string
    {
        $filePath = rtrim($this->templateDir, '/\\') . '/' . $filename;
        if (!file_exists($filePath)) {
            throw new \RuntimeException("Email template not found: {$filename}");
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            throw new \RuntimeException("Unable to read email template: {$filename}");
        }

        foreach ($placeholders as $key => $val) {
            $content = str_replace('{{' . $key . '}}', (string)$val, $content);
        }

        return $content;
    }

    /**
     * Low-level send method.
     */
    public function send(
        string $toEmail,
        string $toName,
        string $subject,
        string $htmlBody,
        string $textBody,
        ?string $auditEventPrefix = null,
        ?int $userId = null
    ): bool {
        $toEmail = trim($toEmail);
        $this->lastError = null;

        if (!filter_var($toEmail, FILTER_VALIDATE_EMAIL)) {
            $this->lastError = "Invalid recipient email address.";
            if ($auditEventPrefix) {
                $this->logger->log("{$auditEventPrefix}_FAILED", 'INVALID_EMAIL', $userId, $toEmail);
            }
            return false;
        }

        try {
            $mailer = $this->createMailer();
            $mailer->addAddress($toEmail, $toName);
            $mailer->Subject = $subject;
            $mailer->isHTML(true);
            $mailer->Body    = $htmlBody;
            $mailer->AltBody = $textBody;

            $sent = $mailer->send();

            if ($sent) {
                if ($auditEventPrefix) {
                    $this->logger->log("{$auditEventPrefix}_SENT", 'SUCCESS', $userId, $toEmail, [
                        'subject' => $subject,
                    ]);
                }
                return true;
            }

            $this->lastError = "Mailer returned false without exception.";
            if ($auditEventPrefix) {
                $this->logger->log("{$auditEventPrefix}_FAILED", 'DELIVERY_FAILED', $userId, $toEmail, [
                    'reason' => 'Mailer returned false',
                ]);
            }
            return false;
        } catch (Throwable $e) {
            $sanitized = $this->sanitizeErrorMessage($e->getMessage());
            $this->lastError = $sanitized;

            if ($auditEventPrefix) {
                $this->logger->log("{$auditEventPrefix}_FAILED", 'EXCEPTION', $userId, $toEmail, [
                    'error' => substr($sanitized, 0, 200),
                ]);
            }

            return false;
        }
    }

    /**
     * Sends a 2FA OTP verification code email.
     *
     * @param string $toEmail User's email address
     * @param string $userName User's display name or first name
     * @param string $rawOtp 6-digit OTP code (transmitted in email body, NEVER logged)
     * @param int|null $userId User ID for audit logging
     * @return bool True if successfully sent, false on failure
     */
    public function sendTwoFactorOtp(string $toEmail, string $userName, string $rawOtp, ?int $userId = null): bool
    {
        $expiryMinutes = (int)(TwoFactorService::OTP_EXPIRY_SECONDS / 60);
        $displayName = !empty(trim($userName)) ? trim($userName) : 'User';

        $vars = [
            'USER_NAME'      => htmlspecialchars($displayName, ENT_QUOTES, 'UTF-8'),
            'OTP'            => $rawOtp,
            'EXPIRY_MINUTES' => $expiryMinutes,
            'YEAR'           => date('Y'),
            'APP_URL'        => self::getAppBaseUrl(),
        ];

        $html = $this->renderTemplate('2fa_otp.html', $vars);
        $text = $this->renderTemplate('2fa_otp.txt', $vars);

        return $this->send(
            $toEmail,
            $displayName,
            'DaakPion - Your Two-Factor Verification Code',
            $html,
            $text,
            '2FA_EMAIL',
            $userId
        );
    }

    /**
     * Sends a Password Reset email.
     *
     * @param string $toEmail User's email address
     * @param string $userName User's name
     * @param string $resetUrl Complete reset URL containing the raw token
     * @param int|null $userId User ID for audit logging
     * @return bool True if successfully sent, false on failure
     */
    public function sendPasswordReset(string $toEmail, string $userName, string $resetUrl, ?int $userId = null): bool
    {
        $expiryMinutes = (int)(PasswordResetService::TOKEN_EXPIRY_SECONDS / 60);
        $displayName = !empty(trim($userName)) ? trim($userName) : 'User';

        $vars = [
            'USER_NAME'      => htmlspecialchars($displayName, ENT_QUOTES, 'UTF-8'),
            'RESET_URL'      => $resetUrl,
            'EXPIRY_MINUTES' => $expiryMinutes,
            'YEAR'           => date('Y'),
            'APP_URL'        => self::getAppBaseUrl(),
        ];

        $html = $this->renderTemplate('password_reset.html', $vars);
        $text = $this->renderTemplate('password_reset.txt', $vars);

        return $this->send(
            $toEmail,
            $displayName,
            'DaakPion - Reset Your Password',
            $html,
            $text,
            'PASSWORD_RESET_EMAIL',
            $userId
        );
    }

    /**
     * Returns the last sanitized delivery error message.
     */
    public function getLastError(): ?string
    {
        return $this->lastError;
    }
}

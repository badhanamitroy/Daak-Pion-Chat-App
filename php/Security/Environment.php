<?php
namespace Daakpion\Security;

/**
 * Environment — Centralized application environment state and safe secret exposure controls.
 *
 * Supported environments:
 * - 'production' (DEFAULT / FAIL-CLOSED)
 * - 'development'
 * - 'test'
 *
 * Rules:
 * - Production MUST NEVER disclose OTPs, reset tokens, or development credentials.
 * - Missing, empty, or unrecognized environment strings strictly default to 'production'.
 * - Loose hostname checks (e.g. 'localhost', '127.0.0.1') are completely prohibited.
 */
class Environment
{
    public const ENV_DEVELOPMENT = 'development';
    public const ENV_TEST        = 'test';
    public const ENV_PRODUCTION  = 'production';

    /**
     * Resolves the current runtime environment name.
     * Defaults to 'production' if undefined, invalid, or unrecognized (fail-closed).
     *
     * @return string 'development' | 'test' | 'production'
     */
    public static function getEnvironment(): string
    {
        $env = null;

        // 1. Check process environment variables first
        $fromGetEnv = getenv('APP_ENV');
        if ($fromGetEnv !== false && $fromGetEnv !== '') {
            $env = $fromGetEnv;
        } elseif (!empty($_ENV['APP_ENV'])) {
            $env = $_ENV['APP_ENV'];
        } elseif (!empty($_SERVER['APP_ENV'])) {
            $env = $_SERVER['APP_ENV'];
        } elseif (defined('APP_ENV') && is_string(APP_ENV) && APP_ENV !== '') {
            $env = APP_ENV;
        }

        $normalized = strtolower(trim((string)$env));
        if (in_array($normalized, [self::ENV_DEVELOPMENT, self::ENV_TEST, self::ENV_PRODUCTION], true)) {
            return $normalized;
        }

        // Secure default: Any unrecognized or missing value is strictly treated as production
        return self::ENV_PRODUCTION;
    }

    /**
     * Checks if current environment is explicitly production.
     */
    public static function isProduction(): bool
    {
        return self::getEnvironment() === self::ENV_PRODUCTION;
    }

    /**
     * Checks if current environment is explicitly development.
     */
    public static function isDevelopment(): bool
    {
        return self::getEnvironment() === self::ENV_DEVELOPMENT;
    }

    /**
     * Checks if current environment is test.
     */
    public static function isTest(): bool
    {
        return self::getEnvironment() === self::ENV_TEST;
    }

    /**
     * Determines whether simulated development tokens/OTPs may be included in output.
     *
     * Guaranteed:
     * - Returns FALSE in production.
     * - Returns FALSE if APP_ENV is invalid or unset.
     * - Returns TRUE only when explicitly configured for development or automated test.
     */
    public static function allowDevSecrets(): bool
    {
        if (self::isProduction()) {
            return false;
        }

        return self::isDevelopment() || self::isTest();
    }
}

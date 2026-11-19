<?php
namespace SLiMS\Turnstile;

use SLiMS\Config;

/** Compatibility adapter for Config 9.7.2/9.8.0, without reloading database settings. */
final class RuntimeConfig
{
    public static function captcha(array $value): void
    {
        $config = Config::getInstance();

        // Neither supported Config exposes a setter for a missing root. load() would
        // reload ALL database settings and can trigger unrelated deserialization errors.
        // Limit private access to the verified storage property and captcha root only.
        $property = new \ReflectionProperty(Config::class, 'configs');
        if (PHP_VERSION_ID < 80100) $property->setAccessible(true);
        $values = $property->getValue($config);
        if (!is_array($values)) throw new \RuntimeException('Config SLiMS tidak kompatibel.');
        if (isset($values['captcha']) && is_array($values['captcha'])) {
            if ($config->replace('captcha', $value)) return;
        }
        $values['captcha'] = $value;
        $property->setValue($config, $values);
    }
}

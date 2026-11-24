<?php

declare(strict_types=1);

namespace WScan\Support;

final class Config
{
    private array $data;

    /** @param array<string,mixed> $data */
    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new \RuntimeException("配置文件不存在: {$path}");
        }
        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new \RuntimeException("无法读取配置文件: {$path}");
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException("配置文件不是合法 JSON: {$path}");
        }

        return new self(self::withDefaults($decoded));
    }

    public static function fromArray(array $data): self
    {
        return new self(self::withDefaults($data));
    }

    /** @param array<string,mixed> $data */
    private static function withDefaults(array $data): array
    {
        $defaults = require dirname(__DIR__, 2) . '/config/defaults.php';

        return self::mergeRecursive($defaults, $data);
    }

    private static function mergeRecursive(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            if (is_array($value) && isset($base[$key]) && is_array($base[$key]) && !array_is_list($value)) {
                $base[$key] = self::mergeRecursive($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }

        return $base;
    }

    /** @return mixed */
    public function get(string $path, mixed $default = null): mixed
    {
        $node = $this->data;
        foreach (explode('.', $path) as $segment) {
            if (!is_array($node) || !array_key_exists($segment, $node)) {
                return $default;
            }
            $node = $node[$segment];
        }

        return $node;
    }

    /** @return list<string> */
    public function getList(string $path): array
    {
        $value = $this->get($path, []);

        return is_array($value) ? array_values(array_map('strval', $value)) : [];
    }

    /** @return array<string,mixed> */
    public function all(): array
    {
        return $this->data;
    }
}

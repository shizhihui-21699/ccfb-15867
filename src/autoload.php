<?php

declare(strict_types=1);

/**
 * Minimal PSR-4 style autoloader for the WScan namespace.
 * No external dependencies are required, which keeps the tool easy to drop
 * onto an old intranet server.
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'WScan\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $file = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

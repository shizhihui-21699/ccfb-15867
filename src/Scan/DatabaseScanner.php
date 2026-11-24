<?php

declare(strict_types=1);

namespace WScan\Scan;

use WScan\Detect\Subject;
use WScan\Detect\DetectorInterface;
use WScan\Finding;
use WScan\Support\Config;
use WScan\Support\Text;

/**
 * Scans database text columns for injected redirects, dark links and encoded
 * payloads.
 *
 * Old PHP CMSes keep article bodies, template fragments and navigation config in
 * the database. An attacker who cannot drop a file will happily write
 * `<script>...</script>` or an obfuscated redirect into a `content` column.
 *
 * Strategy:
 *   - auto-discover text-ish columns (char/varchar/text/json/blob) via schema
 *     introspection, or use an explicit include list
 *   - sample rows per table (deep decode is expensive)
 *   - run the same detectors as the file scanner, with origin
 *     "db:table.column#pk" so the report can point at the exact row
 */
final class DatabaseScanner
{
    /** @param list<DetectorInterface> $detectors */
    public function __construct(
        private readonly Config $config,
        private readonly array $detectors,
    ) {
    }

    /**
     * @return array{findings:list<Finding>, tables:int, rows:int, columns:int, errors:list<string>}
     */
    public function scan(): array
    {
        $dsn = (string) $this->config->get('database.dsn', '');
        if ($dsn === '') {
            return ['findings' => [], 'tables' => 0, 'rows' => 0, 'columns' => 0, 'errors' => ['未配置 database.dsn，跳过数据库扫描']];
        }

        try {
            $pdo = new \PDO($dsn, (string) $this->config->get('database.user', ''), (string) $this->config->get('database.password', ''), [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            ]);
        } catch (\Throwable $e) {
            return ['findings' => [], 'tables' => 0, 'rows' => 0, 'columns' => 0, 'errors' => ['数据库连接失败: ' . $e->getMessage()]];
        }

        $findings = [];
        $errors = [];
        $tableCount = 0;
        $totalRows = 0;
        $totalColumns = 0;

        $tables = $this->discoverTables($pdo);
        $sampleRows = (int) $this->config->get('database.sample_rows', 200);

        foreach ($tables as $table) {
            if (!$this->tableAllowed($table)) {
                continue;
            }
            $tableCount++;

            try {
                $columns = $this->discoverTextColumns($pdo, $table);
            } catch (\Throwable $e) {
                $errors[] = "读取表结构失败 {$table}: " . $e->getMessage();
                continue;
            }
            if ($columns === []) {
                continue;
            }
            $totalColumns += count($columns);

            $pk = $this->primaryKey($pdo, $table);
            $select = array_map(fn (string $c): string => $this->quoteIdent($pdo, $c), $columns);
            if ($pk !== null) {
                array_unshift($select, $this->quoteIdent($pdo, $pk));
            }
            $sql = 'SELECT ' . implode(', ', $select) . ' FROM ' . $this->quoteIdent($pdo, $table) . ' LIMIT ' . $sampleRows;

            try {
                $stmt = $pdo->query($sql);
            } catch (\Throwable $e) {
                $errors[] = "查询失败 {$table}: " . $e->getMessage();
                continue;
            }
            if ($stmt === false) {
                continue;
            }

            while (($row = $stmt->fetch()) !== false) {
                $totalRows++;
                foreach ($columns as $column) {
                    $value = $row[$column] ?? null;
                    if (!is_string($value) || $value === '' || strlen($value) > 1_000_000) {
                        continue;
                    }
                    $rowId = $pk !== null && isset($row[$pk]) ? (string) $row[$pk] : '?';
                    $origin = "db:{$table}.{$column}#{$rowId}";
                    // Skip obviously non-markup short values to save time.
                    if (strlen($value) < 24 && !preg_match('/[<>{}\$]/', $value)) {
                        continue;
                    }

                    $subject = new Subject(
                        content: Text::truncateForAnalysis($value),
                        origin: $origin,
                        kind: 'db',
                        config: $this->config,
                        meta: ['table' => $table, 'column' => $column, 'pk' => $rowId],
                    );

                    foreach ($this->detectors as $detector) {
                        foreach ($detector->inspect($subject) as $finding) {
                            $findings[] = $finding;
                        }
                    }
                }
            }
        }

        return [
            'findings' => $findings,
            'tables' => $tableCount,
            'rows' => $totalRows,
            'columns' => $totalColumns,
            'errors' => $errors,
        ];
    }

    /** @return list<string> */
    private function discoverTables(\PDO $pdo): array
    {
        $driver = (string) $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        if ($driver === 'sqlite') {
            $stmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");

            return $stmt ? array_map('strval', $stmt->fetchAll(\PDO::FETCH_COLUMN)) : [];
        }
        if ($driver === 'mysql') {
            $stmt = $pdo->query('SHOW TABLES');

            return $stmt ? array_map('strval', $stmt->fetchAll(\PDO::FETCH_COLUMN)) : [];
        }
        if ($driver === 'pgsql') {
            $stmt = $pdo->query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'");

            return $stmt ? array_map('strval', $stmt->fetchAll(\PDO::FETCH_COLUMN)) : [];
        }

        return [];
    }

    /** @return list<string> */
    private function discoverTextColumns(\PDO $pdo, string $table): array
    {
        $driver = (string) $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        $textTypes = ['char', 'varchar', 'text', 'tinytext', 'mediumtext', 'longtext', 'json', 'jsonb', 'clob', 'nvarchar', 'ntext'];

        if ($driver === 'sqlite') {
            $stmt = $pdo->query('PRAGMA table_info(' . $this->quoteIdent($pdo, $table) . ')');
            $out = [];
            foreach ($stmt ? $stmt->fetchAll() : [] as $col) {
                $type = strtolower((string) ($col['type'] ?? ''));
                if ($type === '' || $type === 'text' || str_contains($type, 'char') || str_contains($type, 'clob') || str_contains($type, 'json')) {
                    $out[] = (string) $col['name'];
                }
            }

            return $out;
        }

        $stmt = $pdo->query('SELECT * FROM ' . $this->quoteIdent($pdo, $table) . ' WHERE 1=0');
        $out = [];
        if ($stmt === false) {
            return [];
        }
        $colCount = $stmt->columnCount();
        for ($i = 0; $i < $colCount; $i++) {
            $meta = $stmt->getColumnMeta($i);
            if ($meta === false) {
                continue;
            }
            $name = (string) ($meta['name'] ?? '');
            $type = strtolower((string) ($meta['native_type'] ?? $meta['sqlite:decl_type'] ?? ''));
            $declared = strtolower((string) ($meta['pdo_type'] ?? ''));
            if ($name === '') {
                continue;
            }
            foreach ($textTypes as $t) {
                if (str_contains($type, $t) || str_contains($declared, $t)) {
                    $out[] = $name;
                    break;
                }
            }
        }

        return $out;
    }

    private function primaryKey(\PDO $pdo, string $table): ?string
    {
        $driver = (string) $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        try {
            if ($driver === 'sqlite') {
                $stmt = $pdo->query('PRAGMA table_info(' . $this->quoteIdent($pdo, $table) . ')');
                foreach ($stmt ? $stmt->fetchAll() : [] as $col) {
                    if ((int) ($col['pk'] ?? 0) > 0) {
                        return (string) $col['name'];
                    }
                }
            } elseif ($driver === 'mysql') {
                $stmt = $pdo->query('SHOW KEYS FROM ' . $this->quoteIdent($pdo, $table) . " WHERE Key_name = 'PRIMARY'");
                $row = $stmt ? $stmt->fetch() : null;
                if (is_array($row) && isset($row['Column_name'])) {
                    return (string) $row['Column_name'];
                }
            }
        } catch (\Throwable) {
            // best-effort
        }

        return null;
    }

    private function tableAllowed(string $table): bool
    {
        $include = $this->config->getList('database.include_tables');
        if ($include !== [] && !$this->matchesAny($table, $include)) {
            return false;
        }
        $exclude = $this->config->getList('database.exclude_tables');
        if ($exclude !== [] && $this->matchesAny($table, $exclude)) {
            return false;
        }

        return true;
    }

    /** @param list<string> $patterns */
    private function matchesAny(string $table, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if ($pattern === '') {
                continue;
            }
            if ($pattern === $table) {
                return true;
            }
            $regex = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/i';
            if (preg_match($regex, $table)) {
                return true;
            }
        }

        return false;
    }

    private function quoteIdent(\PDO $pdo, string $ident): string
    {
        $driver = (string) $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        if ($driver === 'mysql') {
            return '`' . str_replace('`', '``', $ident) . '`';
        }

        return '"' . str_replace('"', '""', $ident) . '"';
    }
}

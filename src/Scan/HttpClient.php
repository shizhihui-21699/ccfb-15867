<?php

declare(strict_types=1);

namespace WScan\Scan;

/**
 * Tiny HTTP GET client built on cURL with per-request visitor headers.
 * Redirects are NOT followed by default: a 30x that only fires for one visitor
 * profile is itself the finding we are looking for.
 */
final class HttpClient
{
    public function __construct(
        private readonly int $timeout = 8,
        private readonly bool $verifyTls = false,
        private readonly bool $followRedirects = false,
    ) {
    }

    /**
     * @param array<string,string> $headers
     * @return array{status:int,headers:array<string,string>,body:string,error:?string,effective_url:string}
     */
    public function get(string $url, array $headers = []): array
    {
        $ch = curl_init();
        if ($ch === false) {
            return ['status' => 0, 'headers' => [], 'body' => '', 'error' => 'curl_init 失败', 'effective_url' => $url];
        }

        $responseHeaders = [];
        $headerLines = ['Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8'];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => $this->followRedirects,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => max(2, (int) ($this->timeout / 2)),
            CURLOPT_SSL_VERIFYPEER => $this->verifyTls,
            CURLOPT_SSL_VERIFYHOST => $this->verifyTls ? 2 : 0,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_USERAGENT => $headers['User-Agent'] ?? 'WScan/1.0',
            CURLOPT_HEADERFUNCTION => static function ($_ch, string $line) use (&$responseHeaders): int {
                $pos = strpos($line, ':');
                if ($pos !== false) {
                    $name = strtolower(trim(substr($line, 0, $pos)));
                    $responseHeaders[$name] = trim(substr($line, $pos + 1));
                }

                return strlen($line);
            },
        ]);

        $body = curl_exec($ch);
        $error = $body === false ? curl_error($ch) : null;
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $effective = (string) (curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) ?: $url);
        // curl_close() is a no-op since PHP 8.0 and deprecated in 8.5; the handle
        // is freed when it goes out of scope.
        unset($ch);

        return [
            'status' => $status,
            'headers' => $responseHeaders,
            'body' => is_string($body) ? $body : '',
            'error' => $error,
            'effective_url' => $effective,
        ];
    }
}

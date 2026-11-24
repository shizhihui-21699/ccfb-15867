<?php

declare(strict_types=1);

namespace WScan\Detect;

use WScan\Finding;

/**
 * A detector inspects one piece of content (a file, a cached page, a DB field)
 * and returns zero or more findings.
 */
interface DetectorInterface
{
    public function name(): string;

    /** @return list<Finding> */
    public function inspect(Subject $subject): array;
}

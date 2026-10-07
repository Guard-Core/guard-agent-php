<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent;

/**
 * Agent version, reported to the ingestion API as `agent_version` and used in
 * the `User-Agent` header. Mirrors guard_agent/_version.py and the sibling
 * ports; releases are git-tagged, composer.json carries no version field.
 */
final class Version
{
    public const VERSION = '3.2.1';

    /** User-Agent value sent with every request (mirrors guard-agent). */
    public const USER_AGENT = 'guard-agent/' . self::VERSION;
}

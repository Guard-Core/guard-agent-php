<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Exception;

/**
 * Thrown when a dynamic-rules payload cannot be normalized into the model
 * (mirrors the TypeScript InvalidRulesError). The transport catches it and
 * converts the fetch into a null result, exactly like the Python agent's
 * blanket except in fetch_dynamic_rules.
 */
final class InvalidRulesException extends GuardAgentException
{
}

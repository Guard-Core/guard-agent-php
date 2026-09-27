<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardAgent\Transport;

use RenzoFranceschini\GuardAgent\Model\AgentStatus;
use RenzoFranceschini\GuardAgent\Model\DynamicRules;
use RenzoFranceschini\GuardAgent\Model\SecurityEvent;
use RenzoFranceschini\GuardAgent\Model\SecurityMetric;

/**
 * Transport seam, mirroring TransportProtocol (guard_agent/protocols.py).
 * HttpTransport is the real implementation; tests and hosts may inject a
 * fake. Every implementation must honor the agent's failure-isolation
 * contract for the return values: sendEvents/sendMetrics/sendStatus return
 * false on transient failure (the caller requeues) and true on acceptance or
 * intentional drop; they may throw typed transport errors, which the agent
 * converts into requeue + backoff. fetchDynamicRules NEVER throws (mirrors
 * fetch_dynamic_rules): it returns null when the fetch fails so the agent
 * keeps serving its last good rules.
 */
interface TransportInterface
{
    public function initialize(): void;

    /**
     * @param list<SecurityEvent> $events
     */
    public function sendEvents(array $events): bool;

    /**
     * @param list<SecurityMetric> $metrics
     */
    public function sendMetrics(array $metrics): bool;

    public function sendStatus(AgentStatus $status): bool;

    /**
     * Fetch dynamic rules from the SaaS platform (mirrors
     * fetch_dynamic_rules). Returns null when the server has no payload or
     * the fetch fails; never throws.
     */
    public function fetchDynamicRules(): ?DynamicRules;

    /**
     * @return array<string, mixed>
     */
    public function getStats(): array;

    public function close(): void;
}

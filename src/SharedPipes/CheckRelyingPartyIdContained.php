<?php

namespace Laragear\WebAuthn\SharedPipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Str;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;

use function array_map;
use function explode;
use function hash_equals;
use function parse_url;

use const PHP_URL_HOST;

/**
 * This pipe checks if the Relying Party ID from the authenticator data is contained in a list.
 *
 * This list can be either hosts, or special strings like custom identifiers created in mobile
 * or remote apps. If these are domains, it checks if the credential origin is part of one of
 * these entries, otherwise it checks if that origin has an exact match for each entry list.
 *
 * @internal
 */
abstract class CheckRelyingPartyIdContained
{
    use ThrowsCeremonyException;

    /**
     * Create a new pipe instance.
     */
    public function __construct(protected Repository $config)
    {
        //
    }

    /**
     * Handle the incoming WebAuthn Ceremony Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     * @throws \Laragear\WebAuthn\Exceptions\AttestationException
     */
    public function handle(AttestationValidation|AssertionValidation $validation, Closure $next): mixed
    {
        if ($validation->clientDataJson->origin && $this->matches($validation, $validation->clientDataJson->origin)) {
            return $next($validation);
        }

        static::throw($validation, 'Response has an empty origin.');
    }

    /**
     * Check the credential origin matches EXACTLY one entry from the origins list.
     */
    protected function matches(AttestationValidation|AssertionValidation $validation, string $credentialOrigin): bool
    {
        // If the credential origin is a well-formed URL, extract the host from it.
        $credentialOrigin = $this->normalize($validation, $credentialOrigin);

        foreach ($this->origins() as $origin) {
            // If there is an exact match, just proceed.
            if (hash_equals($origin, $credentialOrigin)) {
                return true;
            }

            // If it didn't match, we will try to parse the host and check if is matches that.
            $host = parse_url($origin, PHP_URL_HOST);

            if ($host && (hash_equals($host, $credentialOrigin) || Str::is("*.$host", $credentialOrigin))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalize the credential origin as a host (domain) if able.
     */
    protected function normalize(AttestationValidation|AssertionValidation $validation, string $origin): string
    {
        $url = parse_url($origin);

        if ($url) {
            if (! isset($url['host'], $url['scheme'])) {
                static::throw($validation, 'Response origin is invalid.');
            }

            if ($url['host'] !== 'localhost' && $url['scheme'] !== 'http') {
                static::throw($validation, 'Response not made from a secure server (localhost or HTTPS).');
            }

            return $url['host'];
        }

        return $origin;
    }

    /**
     * Gather all valid origins that this application should accept.
     *
     * @return string[]
     */
    protected function origins(): array
    {
        // This array ensures we always have at least one entry.
        return [
            $this->config->get('webauthn.relying_party.id') ?? parse_url($this->config->get('app.url'), PHP_URL_HOST),
            ...array_map('trim', explode(',', $this->config->get('webauthn.origins', ''))),
        ];
    }
}

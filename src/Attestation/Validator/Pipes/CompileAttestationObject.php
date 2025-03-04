<?php

namespace Laragear\WebAuthn\Attestation\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\AttestationObject;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Attestation\Formats\None;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\CborDecoder;
use Laragear\WebAuthn\Exceptions\AttestationException;
use Laragear\WebAuthn\Exceptions\DataException;
use Laragear\WebAuthn\JsonTransport;

use function is_array;
use function is_string;

/**
 * 12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
 *     structure to obtain the attestation statement format fmt, the authenticator data authData,
 *     and the attestation statement attStmt.
 *
 * 18. Determine the attestation statement format by performing a USASCII case-sensitive match on
 *     fmt against the set of supported WebAuthn Attestation Statement Format Identifier values.
 *
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @internal
 */
class CompileAttestationObject
{
    /**
     * Handle the incoming Attestation Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AttestationException
     */
    public function handle(AttestationValidation $validation, Closure $next): mixed
    {
        $data = $this->decodeCborBase64($validation->json);

        // Here we would receive the attestation formats and decode them. Since we are only
        // supporting the universal "none" format, we can just check if it's equal or not.
        // Who knows if later we may support multiple formats through a simple PHP match.
        if ($data['fmt'] !== 'none') {
            throw AttestationException::make("Format name [{$data['fmt']}] is invalid.");
        }

        try {
            $authenticatorData = AuthenticatorData::fromBinary($data['authData']->getBinaryString());
        } catch (DataException $e) {
            throw AttestationException::make($e->getMessage());
        }

        $validation->attestationObject = new AttestationObject(
            $authenticatorData, new None($data, $authenticatorData), $data['fmt']
        );

        return $next($validation);
    }

    /**
     * Returns an array map from a BASE64 encoded CBOR string.
     *
     * @return array{fmt: string, attStmt: array, authData: \Laragear\WebAuthn\ByteBuffer}
     *
     * @throws \Laragear\WebAuthn\Exceptions\AttestationException
     */
    protected function decodeCborBase64(JsonTransport $request): array
    {
        try {
            $data = CborDecoder::decode(ByteBuffer::decodeBase64Url($request->get('response.attestationObject', '')));
        } catch (DataException $e) {
            throw AttestationException::make($e->getMessage());
        }

        if (! is_array($data)) {
            throw AttestationException::make('CBOR Object is anything but an array.');
        }

        if (! isset($data['fmt']) || ! is_string($data['fmt'])) {
            throw AttestationException::make('Format is missing or invalid.');
        }

        if (! isset($data['attStmt']) || ! is_array($data['attStmt'])) {
            throw AttestationException::make('Statement is missing or invalid.');
        }

        if (! isset($data['authData']) || ! $data['authData'] instanceof ByteBuffer) {
            throw AttestationException::make('Authenticator Data is missing or invalid.');
        }

        return $data;
    }
}

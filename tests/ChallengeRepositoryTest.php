<?php

namespace Tests;

use Illuminate\Contracts\Session\Session as SessionContract;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\Challenge\SessionChallengeRepository;
use Laragear\WebAuthn\JsonTransport;

use function now;

class ChallengeRepositoryTest extends TestCase
{
    public function test_stores_challenge(): void
    {
        $challenge = new Challenge(new ByteBuffer(''), 60, false, []);

        $this->mock(SessionContract::class)
            ->expects('put')
            ->withArgs(function (string $key, Challenge $challenge): bool {
                static::assertSame('_webauthn', $key);
                static::assertSame(60, $challenge->timeout);
                static::assertSame([], $challenge->properties);
                static::assertSame(now()->addMinute()->getTimestamp(), $challenge->expiresAt);
                static::assertFalse($challenge->verify);

                return true;
            });

        $this->app->make(SessionChallengeRepository::class)->store(new AssertionCreation(null), $challenge);
    }

    public function test_stores_challenge_with_options(): void
    {
        $challenge = new Challenge(new ByteBuffer(''), 0, true, ['foo' => 'bar']);

        $this->mock(SessionContract::class)
            ->expects('put')
            ->withArgs(function (string $key, Challenge $incomingChallenge) use ($challenge): bool {
                static::assertSame('_webauthn', $key);
                static::assertSame($challenge, $incomingChallenge);

                return true;
            });

        $this->app->make(SessionChallengeRepository::class)->store(new AssertionCreation(null), $challenge);
    }

    public function test_pulls_valid_challenge(): void
    {
        $challenge = Challenge::random(60, 60);

        $this->mock(SessionContract::class)
            ->expects('pull')
            ->with('_webauthn')
            ->andReturn($challenge);

        static::assertSame($challenge,
            $this->app->make(SessionChallengeRepository::class)->pull(new AssertionValidation(new JsonTransport())));
    }

    public function test_pulls_doesnt_return_non_existent_challenge(): void
    {
        $challenge = Challenge::random(60, -60);

        $this->mock(SessionContract::class)
            ->expects('pull')
            ->with('_webauthn')
            ->andReturn($challenge);

        static::assertNull($this->app->make(SessionChallengeRepository::class)->pull(new AssertionValidation(new JsonTransport())));
    }

    public function test_pulls_doesnt_return_expired_challenge(): void
    {
        $this->mock(SessionContract::class)
            ->expects('pull')
            ->with('_webauthn')
            ->andReturnNull();

        static::assertNull($this->app->make(SessionChallengeRepository::class)->pull(new AssertionValidation(new JsonTransport())));
    }
}

<?php

namespace TechChallenge\Application\DTO\Auth;

class AuthInput
{
    public function __construct(
        public readonly ?string $name = null,
        public readonly ?string $email = null,
        public readonly ?string $password = null,
        public readonly ?string $token = null,
    ) {

    }
}

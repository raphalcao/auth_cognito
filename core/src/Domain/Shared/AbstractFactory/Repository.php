<?php

namespace TechChallenge\Domain\Shared\AbstractFactory;

abstract class Repository
{
    public function __construct(protected readonly DAO $DAO)
    {
    }

    public function getDAO()
    {
        return $this->DAO;
    }

}

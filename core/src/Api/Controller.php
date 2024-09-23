<?php

namespace TechChallenge\Api;

use TechChallenge\Domain\Shared\AbstractFactory\DAO as AbstractFactoryDAO;
use TechChallenge\Domain\Shared\AbstractFactory\Repository as AbstractFactoryRepository;
abstract class Controller
{
    protected readonly AbstractFactoryDAO $AbstractFactoryDAO;

    protected readonly AbstractFactoryRepository $AbstractFactoryRepository;

    public function __construct()
    {
      //
    }

    protected function return(mixed $data = [], int $status = 200)
    {
        return response()->json($data, $status, ["Content-Type: application/json", "Accept: application/json"]);
    }
}

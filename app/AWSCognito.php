<?php

namespace App;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;
use Illuminate\Http\{Response};
use Illuminate\Support\Facades\Log;

class AWSCognito
{
    protected $client;
    protected $userPoolId;
    protected $clientId;
    protected $clientSecret;
    protected $region;

    public function __construct()
    {
        $this->region = env('AWS_REGION');
        $this->userPoolId = env('AWS_COGNITO_USER_POOL_ID');
        $this->clientId = env('AWS_COGNITO_CLIENT_ID');
        $this->clientSecret = env('AWS_COGNITO_CLIENT_SECRET');

        $this->client = new CognitoIdentityProviderClient([
            'version' => 'latest',
            'region'  => $this->region,
            'credentials' => [
                'key'    => env('AWS_ACCESS_KEY_ID'),
                'secret' => env('AWS_SECRET_ACCESS_KEY'),
            ],
        ]);
    }

    public function register($email, $password, $name)
    {
        try {
            $result = $this->client->signUp([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->calculateSecretHash($email),
                'Username' => $email,
                'Password' => $password,
                'UserAttributes' => [
                    [
                        'Name' => 'email',
                        'Value' => $email
                    ],
                    [
                        'Name' => 'name',
                        'Value' => $name
                    ]
                ],
            ]);
            return $result;
        } catch (AwsException $e) {
            Log::error($e->getMessage());
            return false;
        }
    }

    public function login($dto)
    {
        try {
            $result = $this->client->initiateAuth([
                'AuthFlow' => 'USER_PASSWORD_AUTH',
                'ClientId' => $this->clientId,
                'AuthParameters' => [
                    'USERNAME' => $dto->email,
                    'PASSWORD' => $dto->password,
                    'SECRET_HASH' => $this->calculateSecretHash($dto->email)
                ],
            ]);

            $success =  response()->json(
                [
                    'success' => true,
                    'data' => [
                        'type' => 'Authorized',
                        'message' => $result
                    ]
                ],
                Response::HTTP_OK
            );
            return $success->getData(true);
        } catch (AwsException $e) {
            Log::error($e->getMessage());
            $error =  response()->json(['success' => false]);
            if ($e->getStatusCode() == Response::HTTP_BAD_REQUEST) {
                $error =  response()->json(
                    [
                        'success' => false,
                        'data' => [
                            'type' => 'NotAuthorizedException',
                            'message' => 'Incorrect username or password.'
                        ]
                    ],
                    Response::HTTP_BAD_REQUEST
                );
            }
            return $error->getData(true);
        }
    }

    private function calculateSecretHash($username)
    {
        return base64_encode(hash_hmac('sha256', $username . $this->clientId, $this->clientSecret, true));
    }
}

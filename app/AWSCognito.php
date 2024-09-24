<?php

namespace App;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Support\Facades\Auth;
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

    public function register($dto)
    {
        try {
            $result = $this->client->signUp([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->calculateSecretHash($dto->email),
                'Username' => $dto->email,
                'Password' => $dto->password,
                'UserAttributes' => [
                    [
                        'Name' => 'email',
                        'Value' => $dto->email
                    ],
                    [
                        'Name' => 'name',
                        'Value' => $dto->name
                    ]
                ],
            ]);

            $access = [];
            foreach ($result as $data => $value) {
                $access[$data] = $value;
            }

            $success = [
                'success' => true,
                'data' => [
                    'type' => 'Authorized',
                    'message' => $access
                ]
            ];
            return $success;
        } catch (AwsException $e) {
            Log::error($e->getMessage());
            $error =  response()->json(['success' => false]);
            if ($e->getStatusCode() == Response::HTTP_BAD_REQUEST) {
                $error =  response()->json(
                    [
                        'success' => false,
                        'data' => [
                            'type' => 'NotAuthorizedException',
                            'message' => 'SignUp is not permitted for this user pool.'
                        ]
                    ],
                    Response::HTTP_BAD_REQUEST
                );
            }
            return $error->getData(true);
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

            $access = [];
            foreach ($result as $data => $value) {
                $access[$data] = $value;
            }

            $success = [
                'success' => true,
                'data' => [
                    'type' => 'Authorized',
                    'message' => $access
                ]
            ];
            return $success;
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

    /**
     * Logout do usuário e revoga o token.
     */
    public function logout($dto)
    {
        try {
            $result =  $this->client->globalSignOut([
                'AccessToken' => $dto->token,
            ]);

            $access = [];
            foreach ($result as $data => $value) {
                $access[$data] = $value;
            }
            Auth::logout();

            if ($access['@metadata']['statusCode'] == Response::HTTP_OK) {
                $success = [
                    'success' => true,
                    'data' => [
                        'type' => 'User successfully logged out.',
                        'message' => $access
                    ],
                    'status' => Response::HTTP_OK
                ];
            }
            return $success;
        } catch (AwsException $e) {
            Log::error($e->getMessage());
            $error =  response()->json(['success' => false]);
            if ($e->getStatusCode() == Response::HTTP_BAD_REQUEST) {
                $error =  response()->json(
                    [
                        'success' => false,
                        'data' => [
                            'type' => 'NotAuthorizedException',
                            'message' => 'Access Token has been revoked.'
                        ]
                    ],
                    Response::HTTP_BAD_REQUEST
                );
            }
            return $error->getData(true);
        }
        return response()->json(['error' => 'Usuário não autenticado ou token não encontrado'], 401);
    }

    private function calculateSecretHash($username)
    {
        return base64_encode(hash_hmac('sha256', $username . $this->clientId, $this->clientSecret, true));
    }
}

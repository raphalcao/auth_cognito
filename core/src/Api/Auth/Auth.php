<?php

namespace TechChallenge\Api\Auth;

use TechChallenge\Api\Controller;
use Illuminate\Http\{
    Response,
    Request
};

use App\AWSCognito;
use Aws\Exception\AwsException;
use Exception;

class Auth extends Controller
{
    protected $cognito;

    public function __construct(AWSCognito $cognito)
    {
        $this->cognito = $cognito;
    }

    /**
     * Registro de usuário
     */
    public function register(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255',
                'password' => 'required|string|min:8',
            ]);

            $result = $this->cognito->register(
                $validatedData['email'],
                $validatedData['password'],
                $validatedData['name']
            );

            if ($result) {
                return response()->json([
                    'message' => 'User registered successfully'
                ], Response::HTTP_CREATED);
            }

            return response()->json([
                'error' => 'Login failed'
            ], Response::HTTP_BAD_REQUEST);
        } catch (AwsException $e) {
            return response()->json([
                'error' => [
                    'message' => $e->getAwsErrorMessage(),
                    'code' => $e->getAwsErrorCode()
                ]
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        } catch (Exception $e) {
            return response()->json([
                'error' => [
                    'message' => $e->getMessage()
                ]
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Login do usuário
     */
    public function login(Request $request)
    {
        try {
            $validatedData = $request->validate([
                'email' => 'required|string|email|max:255',
                'password' => 'required|string|min:8',
            ]);

            $result = $this->cognito->login($validatedData['email'], $validatedData['password']);

            if ($result) {
                return response()->json([
                    'token' => $result['AuthenticationResult']['AccessToken']
                ], Response::HTTP_OK);
            }

            return response()->json([
                'error' => 'Login failed'
            ], Response::HTTP_UNAUTHORIZED);
        } catch (AwsException $e) {
            return response()->json([
                'error' => [
                    'message' => $e->getAwsErrorMessage(),
                    'code' => $e->getAwsErrorCode()
                ]
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        } catch (Exception $e) {
            return response()->json([
                'error' => [
                    'message' => $e->getMessage()
                ]
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}

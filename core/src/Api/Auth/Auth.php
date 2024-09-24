<?php

namespace TechChallenge\Api\Auth;

use TechChallenge\Application\DTO\Auth\AuthInput;
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

    public function register(Request $request)
    {
        try {
            $this->validateRequest($request, true);

            $dto = new AuthInput($request->name, $request->email, $request->password);

            $result = $this->cognito->register($dto);

            if (isset($result['success']) && $result['success'] == true) {
                return response()->json([
                    'message' => 'User registered successfully'
                ], Response::HTTP_CREATED);
            }

            return response()->json([
                'type' => $result["data"]['type'],
                'error' => $result["data"]['message'],
            ], Response::HTTP_BAD_REQUEST);
        } catch (AwsException $e) {
            return $this->handleAwsException($e);
        } catch (Exception $e) {
            return $this->handleGenericException($e);
        }
    }
    
    public function login(Request $request)
    {
        try {

            $this->validateRequest($request);

            $dto = new AuthInput($request->name, $request->email, $request->password);

            $result = $this->cognito->login($dto);
            if (isset($result['success']) && $result['success'] == true) {

                return response()->json([
                    'token' => $result['data']['message']['AuthenticationResult']['AccessToken']
                ], Response::HTTP_OK);
            }

            return response()->json([
                'type' => $result["data"]['type'],
                'error' => $result["data"]['message'],
            ], Response::HTTP_BAD_REQUEST);
        } catch (AwsException $e) {
            return $this->handleAwsException($e);
        } catch (Exception $e) {
            return $this->handleGenericException($e);
        }
    }

    public function logout(Request $request)
    {
        try {

            $this->validateRequest($request);

            $dto = new AuthInput($request->name, $request->email, $request->password, $_SERVER['HTTP_AUTHORIZATION']);

            $result = $this->cognito->logout($dto);

            $statusCode = $result['status'] ?? Response::HTTP_BAD_REQUEST;

            $responseKey = ($statusCode === Response::HTTP_OK) ? 'success' : 'error';

            return response()->json([
                'type' => $result["data"]['type'] ?? 'unknown',
                $responseKey => $result["data"]['message'] ?? 'No message available',
            ], $statusCode);
        } catch (AwsException $e) {
            return $this->handleAwsException($e);
        } catch (Exception $e) {
            return $this->handleGenericException($e);
        }
    }

    private function handleAwsException(AwsException $e)
    {
        return response()->json([
            'error' => [
                'message' => $e->getAwsErrorMessage(),
                'code' => $e->getAwsErrorCode()
            ]
        ], Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    private function handleGenericException(Exception $e)
    {
        return response()->json([
            'error' => [
                'message' => $e->getMessage()
            ]
        ], Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    private function validateRequest(Request $request, bool $isRegister = false)
    {
        $rules = [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:8',
        ];

        if ($isRegister) {
            $rules['name'] = 'required|string|max:255';
        }

        $messages = [
            'email.required' => 'The email field is required.',
            'email.email' => 'The email field must be a valid email address.',
            'password.required' => 'The password field is required.',
            'password.min' => 'Password must be at least :min characters long.',
            'name.required' => 'The name field is required.',
        ];

        return $request->validate($rules, $messages);
    }
}

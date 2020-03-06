<?php

declare(strict_types = 1);

$requestHeaders = apache_request_headers();
$authorizationHeader = isset($requestHeaders['authorization']) ? $requestHeaders['authorization'] : $requestHeaders['Authorization'];

header('Content-Type: application/json; charset=utf-8');

if ($authorizationHeader == null) {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("message" => "No authorization header sent."));
    exit();
}

$authorizationHeader = str_replace('bearer ', '', $authorizationHeader);
$access_token = str_replace('Bearer ', '', $authorizationHeader);

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/dotenv-loader.php';

use \Auth0\SDK\API\Authentication;

$auth0_api = new Authentication(
    getenv('AUTH0_DOMAIN'),
    getenv('AUTH0_CLIENT_ID'),
    getenv('AUTH0_CLIENT_SECRET')
);

$user_info = $auth0_api->userinfo($access_token);
if(!isset($user_info)) {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("success" => False, "message" => "user_info invalid"));
    exit();
}

$email = $user_info["email"];
if(!isset($email)) {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("success" => False, "message" => "email missing"));
    exit();
}

$data = json_decode(file_get_contents('php://input'), true);

$otp = $data["otp"];
if(!isset($otp)) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => "otp missing"));
    exit();
}

$new_email = $data["new_email"];
if(!isset($otp)) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => "new email missing"));
    exit();
}

$source_ip = $_SERVER['REMOTE_ADDR'];

$authParams = array(
    'response_type' => 'id_token',
    'scope' => 'openid email'
);

$option = array(
    'grant_type' => 'http://auth0.com/oauth/grant-type/passwordless/otp',
    'username' => $email,
    'realm' => 'email',
    'otp' => $otp,
    'auth0_forwarded_for' => $source_ip

);


try {
    $result = $auth0_api->oauth_token($option);
} catch (Exception $e) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => $e->getMessage()));
    exit();
}

if(!isset($result['access_token'])) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => 'access_token missing'));
    exit();
}

$id_token = $result['id_token'];
if(!isset($id_token)) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => 'id_token missing'));
    exit();
}

use Auth0\SDK\Helpers\JWKFetcher;
use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\IdTokenVerifier;

$token_issuer  = 'https://'.getenv('AUTH0_DOMAIN').'/';
$jwks_fetcher = new JWKFetcher();
$jwks        = $jwks_fetcher->getKeys($token_issuer.'.well-known/jwks.json');
$signature_verifier = new AsymmetricVerifier($jwks);
$token_verifier = new IdTokenVerifier(
    $token_issuer,
    getenv('AUTH0_CLIENT_ID'),
    $signature_verifier
);

try {
    $decoded_id_token = $token_verifier->verify($id_token);
} catch (\Exception $e) {
    echo 'Caught: Exception - '.$e->getMessage();
}

$id_token_email = $decoded_id_token['email'];
if($email != $id_token_email) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => 'email mismatch'));
    exit();

}

$authParams = array(
    'response_type' => 'id_token',
);

try {
    $auth0_api->email_passwordless_start($new_email, 'code', $authParams, $source_ip);
} catch (Exception $e) {
    header('HTTP/1.0 500 Error');
    echo json_encode(array("success" => False, "message" => $e->getMessage()));
    exit();
}

echo json_encode(array("success" => True, "message" => 'email verified', 'otp_access_token' => $result['access_token']));
exit();

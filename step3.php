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

$user_id = $user_info["sub"];
if(!isset($email)) {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("success" => False, "message" => "sub missing"));
    exit();
}

$data = json_decode(file_get_contents('php://input'), true);

$new_otp = $data["new_otp"];
if(!isset($new_otp)) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => "new_otp missing"));
    exit();
}

$new_email = $data["new_email"];
if(!isset($new_email)) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => 'new_email missing'));
    exit();
}

$otp_access_token = htmlspecialchars($_COOKIE["otp_access_token"]);
if(!isset($otp_access_token)) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => "otp_access_token missing"));
    exit();
}

$otp_user_info = $auth0_api->userinfo($otp_access_token);
if(!isset($otp_user_info)) {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("success" => False, "message" => "user_info invalid"));
    exit();
}

$otp_user_info_email = $otp_user_info['email'];
$otp_user_info_sub = $otp_user_info['sub'];

if($otp_user_info_sub === $user_id) {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("success" => False, "message" => "otp and email users are the same"));
    exit();
}

if(! isset($otp_user_info_email) || !isset($otp_user_info_sub)) {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("success" => False, "message" => "otp user_info invalid"));
    exit();
}

if(substr( $otp_user_info_sub, 0, 6 ) !== "email|") {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("success" => False, "message" => "otp access_token not from email"));
    exit();
}

if($otp_user_info_email !== $email) {
    header('HTTP/1.0 401 Unauthorized');
    echo json_encode(array("success" => False, "message" => "users do not match"));
    exit();
}

$source_ip = $_SERVER['REMOTE_ADDR'];

$option = array(
    'grant_type' => 'http://auth0.com/oauth/grant-type/passwordless/otp',
    'username' => $new_email,
    'realm' => 'email',
    'otp' => $new_otp,
    'auth0_forwarded_for' => $source_ip
);

try {
    $result = $auth0_api->oauth_token($option);
} catch (Exception $e) {
   header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => $e->getMessage()));
    exit();
}

$new_id_token = $result['id_token'];
if(!isset($new_id_token)) {
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
    $decoded_id_token = $token_verifier->verify($new_id_token);
} catch (Exception $e) {
    header('HTTP/1.0 400 Bad Request');
    echo json_encode(array("success" => False, "message" => 'id_token validation failed'));
    exit();
}

// Both current user and new OTP verified, let's go...
$AUTH0_MANAGEMENT_AUDIENCE = 'https://' . getenv('AUTH0_DOMAIN') . '/api/v2/';
$config = [
    'audience' => $AUTH0_MANAGEMENT_AUDIENCE
];

try {
    $result = $auth0_api->client_credentials($config);
} catch (Exception $e) {
    header('HTTP/1.0 500 Internal Server Error');
    echo json_encode(array("success" => False, "message" => 'M2M creds failed'));
    exit();
}

$management_access_token = $result["access_token"];

use Auth0\SDK\API\Management;

$management_api = new Management( $management_access_token, getenv('AUTH0_DOMAIN') );

try {
    $management_api->users()->delete($otp_user_info_sub);
} catch (Exception $e) {
    header('HTTP/1.0 500 Internal Server Error');
    echo json_encode(array("success" => False, "message" => 'current OTP user delete failed'));
    exit();
}

try {
    $management_api->users()->delete($decoded_id_token['sub']);
} catch (Exception $e) {
    header('HTTP/1.0 500 Internal Server Error');
    echo json_encode(array("success" => False, "message" => 'new OTP user delete failed'));
    exit();
}

try {
    $management_api->users()->update($user_id, array('email' => $new_email, 'email_verified' => True));
} catch (Exception $e) {
    header('HTTP/1.0 500 Internal Server Error');
    echo json_encode(array("success" => False, "message" => "update failed user: $user_id to email $new_email",
        "error" => $e->getMessage()));
    exit();
}

setcookie('otp_access_token', '', time() - 3600);
echo json_encode(array("success" => True, 'message' => 'email changed'));

exit();

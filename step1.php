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

$source_ip = $_SERVER['REMOTE_ADDR'];

$authParams = array(
    'response_type' => 'id_token',
    'scope' => 'openid email'
);

try {
    $auth0_api->email_passwordless_start($email, 'code', $authParams, $source_ip);
} catch (Exception $e) {
    header('HTTP/1.0 500 Error');
    echo json_encode(array("success" => False, "message" => $e->getMessage()));
    exit();
}

echo json_encode(array("success" => True, "message" => "OTP code sent"));
exit();

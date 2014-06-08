<?php
$_GET['cmd'] = 'callback';
$_GET['module'] = 'alipay2';
$_GET['ali_type_r'] = 'callback';
error_reporting( 0 );
session_name('SESSID' . substr(md5($_SERVER['SERVER_NAME']), -4));
session_start();
include('../../../../../hbf/bootstrap.php');
FrontController::init( 'module' );

<?php

include_once("include/header.php");

//check if is logged in, if yes redirect to main page

global $login_status;
if ($login_status === 1) {
	redirect("main.php");
}
$page_title = 'Login';
$tpl = 'login.tpl.php';
include 'include/template.php';
exit;

?>

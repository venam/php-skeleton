<?php

include_once("include/functions.php");

$dbConnection = get_db_handle();
sec_session_start(); 
$login_status = login_check($dbConnection);
if ($login_status !== 1 &&
	!(preg_match(
		"/login.php/i",
		$_SERVER['REQUEST_URI']))
	) {
	logout();
	redirect("login.php");
}

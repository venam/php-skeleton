<?php

require_once("config.php");


function get_db_handle() {
	global $db_config;
	return new PDO($db_config['host'], $db_config['user'], $db_config['password']);
}


function sec_session_start() {
    $session_name = 'sec_session_id';   // Set a custom session name
    $secure = false;
    // This stops JavaScript being able to access the session id.
    $httponly = true;
    // Forces sessions to only use cookies.
    if (ini_set('session.use_only_cookies', 1) === FALSE) {
        header("Location: ../error.php?err=Could not initiate a safe session (ini_set)");
        exit();
    }
    // Gets current cookies params.
    $cookieParams = session_get_cookie_params();
    session_set_cookie_params($cookieParams["lifetime"],
        $cookieParams["path"], 
        $cookieParams["domain"], 
        $secure,
        $httponly);
    // Sets the session name to the one set above.
    session_name($session_name);
    session_start();            // Start the PHP session 
    session_regenerate_id(true);    // regenerated the session, delete the old one. 
}


function printd($msg) {
	if(DEBUG) {
		print "<b>$msg</b><br/>\n";
	}
}


function redirect($page) {
	header("Location: $page", TRUE, 301);
	exit();
}


function get_ip() {
	$ip_address = $_SERVER['REMOTE_ADDR'];
	if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
		$ip_address = array_pop(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
	}
	return $ip_address;
}


function login_check($psql) {
	/*
	 * one user agent and one ip per user
	 */
	if(isset($_SESSION['user_id'],
		$_SESSION['username'],
		$_SESSION['login_string'])){

		$user_id = $_SESSION['user_id'];
		$login_string = $_SESSION['login_string'];
		//$username = $_SESSION['username'];

		//disable the use of another user agent
		$user_browser = $_SERVER['HTTP_USER_AGENT'];
		$ip_address = get_ip();
		printd("ip address is: $ip_address");
		printd("user agent is: $user_browser");

		$query = "SELECT
			uid, username, pass, user_agent, current_ip
			FROM users
			WHERE uid = ?
			LIMIT 1";
		$sth = $psql->prepare($query);
		$sth->execute(array($user_id));
		$result = $sth->fetchAll();
		if(count($result) != 1) {
			printd("no result from query");
			return -2;
		}
		else {
			$result = $result[0];
			printd(var_dump($result));
			$password_hash = $result["pass"];
			//$d_username = $result['username'];
			$d_user_agent = $result['user_agent'];
			$d_current_ip = $result['current_ip'];
			$login_check = hash('sha512',
				$password_hash . $d_user_agent . $d_current_ip);
			printd("login check string: $login_check");
			printd("current string: $login_string");
			if($login_check == $login_string) {
				printd("user is logged in");
				return 1;
			}
			else {
				printd("session has expired, the login string doesn't match");
				return -3;
			}
		}
	}
	else {
		printd("session not started yet");
		return -1;
	}
}


function logout() {
	$_SESSION = array();
	$params = session_get_cookie_params();
	setcookie(session_name(),
		'', time() - 42000,
		$params["path"],
		$params["domain"],
		$params["secure"],
		$params["httponly"]);
	session_destroy();
}


function is_admin($username) {
	/*
	 * TODO: use a list of restricted ips too
	 * only them can access the admin page
	 */
	global $admins;
	return (in_array($username, $admins));
}


function login($username, $password, $psql) {
	$query = "SELECT 
	id, username, password, type
	FROM users
	WHERE username = ?
	LIMIT 1"; 

	$sth = $psql->prepare($query);
	$sth->execute(array($username));
	$result = $sth->fetchAll();
	if (count($result) != 1) {
		return -1;
	}
	else {
		$password_hash = $result[0]["password"];
		$type = $result[0]["type"];
		$id = $result[0]["id"];
		$user_browser = $_SERVER['HTTP_USER_AGENT'];

		if (password_verify($password, $password_hash)){ //right password
			$login_check = hash('sha512', $password_hash . $user_browser . $ip_address);
			$_SESSION['login_string'] = $login_check;
			$_SESSION['user_id'] =  $id;
			$_SESSION['username'] = $username;
			if ($type=="admin") {
				return 0;
			}
			else if ($type == "superadmin") {
				return 2;
			}
			else {
				return 1;
			}
		}
		else {
			return -1;
		}
	}
}


function change_password($password, $psql){
	$query = "UPDATE users
		set password = ?
		WHERE id = ?";
	$user_id = $_SESSION['user_id'];
	$sth = $psql->prepare($query);
	$password_hash = password_hash($password, PASSWORD_BCRYPT);
	$sth->execute(array($password_hash, $user_id));

	$user_browser = $_SERVER['HTTP_USER_AGENT'];
	$query = "SELECT 
	id, username, password, type
	FROM users
	WHERE username = ?
	LIMIT 1"; 
	$sth = $psql->prepare($query);
	$sth->execute(array($_SESSION["username"]));
	$result = $sth->fetchAll();
	$type = $result[0]["type"];
	$login_check = hash('sha512', $password_hash . $user_browser . $type);
	$_SESSION['login_string'] = $login_check;
}

function create_user($username, $password, $type, $psql) {
	$query = "INSERT INTO users
	values(nextval('user_id'),?,?,?);";

	$password_hash = password_hash($password, PASSWORD_BCRYPT);
	$sth = $psql->prepare($query);
	return $sth->execute(array($username, $type, $password_hash));
}

function esc_url($url) {
    if ('' == $url) {
        return $url;
    }
 
    $url = preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\\x80-\\xff]|i', '', $url);
 
    $strip = array('%0d', '%0a', '%0D', '%0A');
    $url = (string) $url;
 
    $count = 1;
    while ($count) {
        $url = str_replace($strip, '', $url, $count);
    }
 
    $url = str_replace(';//', '://', $url);
 
    $url = htmlentities($url);
 
    $url = str_replace('&amp;', '&#038;', $url);
    $url = str_replace("'", '&#039;', $url);
 
    if ($url[0] !== '/') {
        // We're only interested in relative links from $_SERVER['PHP_SELF']
        return '';
    } else {
        return $url;
    }
}



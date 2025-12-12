<html>
 <head>
 	<title>SQL injection</title>
 	<style>
 		body{
 		}
 		.user {
 			background-color: yellow;
 		}
 	</style>
 </head>
 
 <body>
 	<h1>PDO vulnerable a SQL injection</h1>
 
 	<?php
		if (isset($_POST["user"])) {

			$dbhost = $_ENV["DB_HOST"];
			$dbname = $_ENV["DB_NAME"];
			$dbuser = $_ENV["DB_USER"];
			$dbpass = $_ENV["DB_PASSWORD"];

			$pdo = new PDO("mysql:host=$dbhost;dbname=$dbname", $dbuser, $dbpass);
			$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

			$username = $_POST["user"];
			$pass     = $_POST["password"];

			// Consulta segura con parámetros
			$qstr = "SELECT * FROM users WHERE name = :name AND password = SHA2(:pass, 512);";
			$consulta = $pdo->prepare($qstr);

			// Bind de parámetros
			$consulta->bindParam(':name', $username, PDO::PARAM_STR);
			$consulta->bindParam(':pass', $pass, PDO::PARAM_STR);

			// Para debug (opcional, no imprime contraseñas reales)
			echo "<br>$qstr<br>";

			// Ejecutar consulta
			$consulta->execute();

			# Gestió d'errors
			if( $consulta->errorInfo()[1] ) {
				echo "<p>ERROR: ".$consulta->errorInfo()[2]."</p>\n";
				die;
			}

			if ($consulta->rowCount() >= 1) {
				foreach ($consulta as $user) {
					echo "<div class='user'>Hola ".$user["name"]." (".$user["role"].").</div>";
				}
			} else {
				echo "<div class='user'>No hi ha cap usuari amb aquest nom i contrasenya.</div>";
			}
		}
	?>

 	
 	<fieldset>
 	<legend>Login form</legend>
  	<form method="post">
		User: <input type="text" name="user" /><br>
		Pass: <input type="text" name="password" /><br>
		<input type="submit" value="Login" /><br>
 	</form>
  	</fieldset>
	
 </body>
 
 </html>

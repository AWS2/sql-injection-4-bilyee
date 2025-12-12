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

			try {
				// Insertar nuevo usuario con rol "user"
				$qstr = "INSERT INTO users (name, email, role, password) VALUES (:name, :email, 'user', SHA2(:pass, 512));";
				$consulta = $pdo->prepare($qstr);

				// Email generado automáticamente basado en el nombre
				$email = $username . "@mydomain.com";

				// Bind de parámetros
				$consulta->bindParam(':name', $username, PDO::PARAM_STR);
				$consulta->bindParam(':email', $email, PDO::PARAM_STR);
				$consulta->bindParam(':pass', $pass, PDO::PARAM_STR);

				// Para debug (opcional, no imprime contraseñas reales)
				echo "<br>$qstr<br>";

				// Ejecutar consulta
				$consulta->execute();

				// Mostrar mensaje de éxito
				echo "<div class='user'>Usuari $username creat correctament.</div>";

			} catch (PDOException $e) {
				// Si hay error (ej: usuario ya existe)
				if( strpos($e->getMessage(), 'Duplicate entry') !== false ) {
					echo "<div class='user'>ERROR: El usuario $username ya existe.</div>";
				} else {
					echo "<div class='user'>ERROR: ".$e->getMessage()."</div>";
				}
			}
		}
	?>

 	
 	<fieldset>
 	<legend>Registre form</legend>
  	<form method="post">
		User: <input type="text" name="user" /><br>
		Pass: <input type="text" name="password" /><br>
		<input type="submit" value="Registre" /><br>
 	</form>
  	</fieldset>
	
 </body>
 
 </html>
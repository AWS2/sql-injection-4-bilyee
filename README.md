# SQL injection - exercici

En aquest repositori podem veure un exemple de formulari en PHP vulnerable a SQL injection.

Disposeu de més informació a https://bytes.cat/sql_injection

## Instal·lació

Instal·la Docker:

    $ sudo apt update
    $ sudo apt install docker.io docker-compose-v2

Posa en marxa el servidor amb (cal tenir instal·lat `Docker.io`):

    $ ./run.sh

Pots veure la web d'un senzill login vulnerable per SQL injection a:

    http://localhost:8000

Pots provar d'entrar amb els usuaris que aparèixen al script `sqlscripts/init-db.sql` com pepa/pepa123, etc.

Per parar el servidor pots fer:

    $ ./stop.sh

## Atac de SQL injection

Pots mirar d'atacar el formulari de login posant com a usuari:

    pepa'; -- 

## Exercici

L'exercici consisteix en crear un arxiu `src/index2.php` que sigui com el formulari de login inicial, però que resisteixi els atacs de SQL injection com el de l'exemple anterior.

## Tests

Per passar els tests cal fer:

    $ cd .test
    $ npm install

Per córrer els tests un a un (cal substituir el nom de l'arxiu 01-page-h1.js pels altres tests):

    $ node <XX-test-desc.js>

Per exemple:

    $ node 01-page-h1.js

Per passar tots els tests seguits amb Jest:

    $ npm test

Per passar els del form vulnerable:

    $ npm test form-vulnerable

Per passar els del form "invulnerable":

    $ npm test form-invulnerable

Si vols veure el desenvolupament dels tests en el browser (desactivant el mode HEADLESS) pots fer:

    $ HEADLESS=false npm test form-invulnerable

// carreguem les llibreries
const { BaseTest } = require("./BaseTest.js")
const { By, until } = require("selenium-webdriver");
const assert = require('assert');

// heredem una classe amb un sol mètode test()
// emprem this.driver per utilitzar Selenium

class MyTest extends BaseTest
{
	async test() {
        // testejem ATAC SQL injection exitós
        //////////////////////////////////////////////////////
        let user = "pepa'; -- ";
        let pass = "skdjfksdjfhkdsjfhkjsd";
        // esperar a que el servidor es posi online
        await this.driver.sleep(6000);
        // accedim al web
        await this.driver.get("http://localhost:8000/index2.php");
        await this.driver.findElement(By.name("user")).sendKeys(user);
        await this.driver.findElement(By.name("password")).sendKeys(pass);
        await this.driver.findElement(By.xpath("//input[@value='Login']")).click();
        await this.driver.sleep(1000);

        // comprovem que el message és ERRONI
        let resultText = await this.driver.findElement(By.xpath("//div[@class='user']")).getText();
        let assertMessage = "No hi ha cap usuari amb aquest nom i contrasenya.";
        assert(resultText==assertMessage,`ERROR TEST: L'atac de SQL injection hauria de fallar a index2.php .\nAtac provat: ${user}`);
        
        console.log("TEST OK");
	}
}

async function mytest() {
    const test = new MyTest();
    return await test.run();
}

// executem el test si estem al main
if( require.main === module) {
    mytest();
}

// exports del test
exports.mytest = mytest;

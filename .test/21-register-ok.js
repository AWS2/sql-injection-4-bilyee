// carreguem les llibreries
const { BaseTest } = require("./BaseTest.js")
const { By, until } = require("selenium-webdriver");
const assert = require('assert');

// heredem una classe amb un sol mètode test()
// emprem this.driver per utilitzar Selenium

class MyTest extends BaseTest
{
	async test() {
        // testejem REGISTRE usuari predefinit
        //////////////////////////////////////////////////////

        // creem user amb credencials aleatòries
        const user = Math.random().toString(36).slice(2,12);;
        const pass = Math.random().toString(36).slice(2,12);;
        // esperar a que el servidor es posi online
        await this.driver.sleep(6000);
        // accedim al web
        await this.driver.get("http://localhost:8000/registre.php");
        await this.driver.findElement(By.name("user")).sendKeys(user);
        await this.driver.findElement(By.name("password")).sendKeys(pass);
        await this.driver.findElement(By.xpath("//input[@value='Registre']")).click();
        await this.driver.sleep(1000);

        // comprovem que el missatge de registre és CORRECTE
        let resultText = await this.driver.findElement(By.xpath("//div[contains(@class,'user')]")).getText();
        let assertMessage = `Usuari ${user} creat correctament.`;
        assert(resultText==assertMessage,`ERROR TEST: l'usuari ${user} hauria d'entrar amb el missatge '`+assertMessage+`' en un div.user`);
        console.log(assertMessage);

        // comprovem que podem logar-nos amb l'usuari creat
        await this.driver.get("http://localhost:8000/");
        await this.driver.findElement(By.name("user")).sendKeys(user);
        await this.driver.findElement(By.name("password")).sendKeys(pass);
        await this.driver.findElement(By.xpath("//input[@value='Login']")).click();
        await this.driver.sleep(1000);
        // comprovem que el missatge de login és CORRECTE
        resultText = await this.driver.findElement(By.xpath("//div[contains(@class,'user')]")).getText();
        assertMessage = `Hola ${user} (user).`;
        assert(resultText==assertMessage,`ERROR TEST: l'usuari ${user}/${pass} hauria d'entrar amb el missatge '`+assertMessage+`' en un div.user`);
        console.log(assertMessage);
        
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

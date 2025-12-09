const {Builder, Browser, By, Key, until} = require("selenium-webdriver");
const firefox = require('selenium-webdriver/firefox');
const chrome = require('selenium-webdriver/chrome');
const { spawn } = require("child_process");
const assert = require('assert');


class BaseTest {

    constructor() {
        console.log("Constructing...")
        this.headless = process.env.HEADLESS=="false" ? false : true;
        this.browser = process.env.CHROME_TESTS ? "chrome" : "firefox";
        this.cmd = null;
        this.driver = null;
    }
    
    async setUp() {
        console.log("HEADLESS:"+this.headless);
        console.log("BROWSER:"+this.browser);

        // run server and setup driver
        await this.runServer( "../run", [] );
        await this.setupDriver();
        // deixem temps a que el servidor es posi en marxa
        await this.driver.sleep(2000);
    }

    async tearDown() {
        console.log("Closing server...");
        // parem server
        await this.runServer( "../stop", [] );
        //await this.killServer();
        // deixem temps perquè es tanquin els processos
        await this.driver.sleep(2000);
        // tanquem browser
        console.log("Closing Selenium driver...");
        await this.driver.quit();
    }

    async run() {
        let error = 0; // no error
        console.log("running setUp...");
        await this.setUp();
        try {
            console.log("running test...");
            await this.test();
        } catch (err) {
            // error detected
            error = err;
            console.error(err);
        } finally {
            console.log("running tearDown...");
            await this.tearDown();
            if( error ) {
                throw error;
                return error;
            }
            return 0;
        }
        return "ERROR in run";
    }

    async test() {
        console.log("Empty test!");
    }

    async setupDriver() {
        let firefoxOptions = new firefox.Options();
        let chromeOptions = new chrome.Options();
        if( this.headless ) {
            console.log("Running Headless Tests...");
            firefoxOptions = new firefox.Options().addArguments('-headless');
            chromeOptions = new chrome.Options().addArguments('--headless=new');
        }
        if( this.browser=="chrome" ) {
            this.driver = await new Builder()
                .forBrowser(Browser.CHROME)
                .setChromeOptions(chromeOptions)
                .build();
        } else {
            this.driver = await new Builder()
                .forBrowser(Browser.FIREFOX)
                .setFirefoxOptions(firefoxOptions)
                .build();
        }

        // Configurar timeouts
        await this.driver.manage().setTimeouts({
          implicit: 15000, // 10 segons per trobar elements
          pageLoad: 25000, // 15 segons per carregar pàgines
          script: 50000    // 30 segons per scripts
        });
    }

    runServer( command, options ) {
        // Engeguem server amb la APP
        let app = null;
        if( process.platform=="win32" ) {
            app = spawn(command+".bat",options,{shell:true});
        } else {
            // linux, macos (darwin), or other
            app = spawn(command+".sh",options);
        }
        this.cmd = app;
        return new Promise((resolveFunc) => {
            app.stdout.on("data", data => {
                console.log(`stdout: ${data}`);
            });
            app.stderr.on("data", data => {
                console.log(`stderr: ${data}`);
            });
            app.on('error', (error) => {
                console.log(`error: ${error.message}`);
            });
            app.on("close", code => {
                resolveFunc(code);
                console.log(`child process exited with code ${code}`);
            });
        });
    }

    async killServer() {
        // tanquem servidor
        if( process.platform=="win32" ) {
            spawn("taskkill", ["/pid", this.cmd.pid, '/f', '/t']);
        } else {
            // Linux, MacOS or other
            await this.cmd.kill("SIGHUP")
        }
    }

}

// publiquem l'objecte BaseTest
exports.BaseTest = BaseTest;

const { mytest: test01 } = require("./01-page-h1.js")
const { mytest: test02 } = require("./02-login-error-pwd.js")
const { mytest: test03 } = require("./03-login-error-user.js")
const { mytest: test04 } = require("./04-login-ok.js")
const { mytest: test05 } = require("./05-sqli-attack-ok.js")

describe("Vulnerable Login Form", () => {
	test("01 Header H1 de la pàgina correcte", async () => {
		const code = await test01();
		expect(code).toBe(0);
	}, 30000);

	test("02 Error de password en el login, usuari correcte", async () => {
		const code = await test02();
		expect(code).toBe(0);
	}, 30000);

	test("03 Error de user en el login", async () => {
		const code = await test03();
		expect(code).toBe(0);
	}, 30000);

	test("04 Login exitós", async () => {
		const code = await test04();
		expect(code).toBe(0);
	}, 30000);

	test("05 atac SQL injection exitós (formulari vulnerable)", async () => {
		const code = await test05();
		expect(code).toBe(0);
	}, 30000);
});

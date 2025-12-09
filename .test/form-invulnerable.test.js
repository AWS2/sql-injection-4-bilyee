
const { mytest: test12 } = require("./12-login-error-pwd.js")
const { mytest: test13 } = require("./13-login-error-user.js")
const { mytest: test14 } = require("./14-login-ok.js")
const { mytest: test15 } = require("./15-sqli-attack-fails.js")


describe("Invulerable Login Form", () => {

	test("12 Error de password en el login, usuari correcte (index2.php)", async () => {
		const code = await test12();
		expect(code).toBe(0);
	}, 30000);

	test("13 Error de user en el login (index2.php)", async () => {
		const code = await test13();
		expect(code).toBe(0);
	}, 30000);

	test("14 Login exitós (index2.php)", async () => {
		const code = await test14();
		expect(code).toBe(0);
	}, 30000);

	test("15 atac de SQLi a index2.php ha de fallar", async () => {
		const code = await test15();
		expect(code).toBe(0);
	}, 30000);

});



const { mytest: test21 } = require("./21-register-ok.js")

describe("Registre d'usuaris", () => {
	test("21 formulari de registre", async () => {
		const code = await test21();
		expect(code).toBe(0);
	}, 30000);

});

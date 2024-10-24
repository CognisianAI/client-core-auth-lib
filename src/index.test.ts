import {  test } from "vitest";
import {  GenLoginToken } from "./index";

test("AuthUser function", async () => {
    const [tk, e] = await GenLoginToken(
        "http://localhost:4000",
        "user1@cognisian.com",
        "test",
    );
    if (e != "") {
        console.log("Error in GenLoginToken", e);
        return;
    }
    console.log("Token", tk);
});

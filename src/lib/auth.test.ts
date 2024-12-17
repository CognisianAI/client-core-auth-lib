import { test } from "vitest";
import {  AuthUser } from "./auth";
import {
    publicKeyFromPrivateKey,
    seedToPrivateKey,
    signMessage,
    verifySig,
} from "./keypair";


test("AuthUser function", async () => {
    const [tk, e] = await AuthUser(
        "http://localhost:4000",
        "user1@cognisian.com",
        "test",
    );
    if (e != "") {
        console.log("Error in AuthUser", e);
        return;
    }
    console.log("Token", tk);
});

test("seedToPrivateKey function", async () => {
    const privKey = await seedToPrivateKey("test");
    console.log("Private Key", privKey);

    const pubKey = await publicKeyFromPrivateKey(privKey);
    console.log("Public Key", pubKey);

    const sig = await signMessage(privKey, "test");
    console.log("Signature", sig);

    const isValid = await verifySig("test", sig, pubKey);
    console.log("Signature Verification", isValid);
});

import { Sha256 } from "@aws-crypto/sha256-js";
import {  seedToPrivateKey, signMessage } from "./keypair";
import { bytesToHex } from "@noble/hashes/utils";

type AuthUserFn = (
  endpoint: string,
  email: string,
  password: string,
) => Promise<[string, string]>;
type DeauthUserFn = (
  endpoint: string,
  authToken: string,
) => Promise<[null, string]>;

const API_AUTH_PATH = `/auth`;

const AuthUser: AuthUserFn = async (endpoint, email, password) => {
  const hash = new Sha256();
  hash.update(email+password);
  const passHash = await hash.digest();

  const privateKey = await seedToPrivateKey(bytesToHex(passHash));

  const session_seed = new Date().valueOf().toString();

  const sig = await signMessage(privateKey, session_seed);

  const url = `${endpoint}` + API_AUTH_PATH + "/login";
  const options = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    }, // Required for CORS support to work
    body: JSON.stringify({
      email: email,
      session_seed: session_seed,
      signature: sig,
    }),
  };
  try {
    const result = await fetch(url, options);
    if (result.ok) {
      const data = await result.json();
      return [data.token, ""];
    }
    if (result.status === 401) {
      return ["", "Invalid email or password"];
    }
    return ["", "Unknown error"];
  } catch (e) {
    return ["", "something went wrong" + e];
  }
};

const DeauthUser: DeauthUserFn = async (endpoint, authToken) => {
  const url = `${endpoint}` + API_AUTH_PATH + "/logout";
  const options = {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      Authorization: `Bearer ${authToken}`,
    }, // Required for CORS support to work
  };
  try {
    const result = await fetch(url, options);
    if (result.ok) {
      return [null, ""];
    }
    if (result.status === 401) {
      const resultData = await result.json();
      return [null, resultData.error];
    }
    if (result.status === 403) {
      return [null, "Forbidden"];
    }
    return [null, "Unknown error"];
  } catch (e) {
    return [null, "something went wrong" + e];
  }
};

type GenLoginTokenFn = (
  endpoint: string,
  email: string,
  password: string,
) => Promise<[string, string]>;

const GenLoginToken: GenLoginTokenFn = async (endpoint, email, password) => {
  const request = JsonRpcRequest("TestingService.GenLoginToken", [{
    email,
    password,
  }]);
  const url = `${endpoint}/api/v1`;
  const options = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    }, // Required for CORS support to work
    body: JSON.stringify(request),
  };
  try {
    const result = await fetch(url, options);
    if (result.ok) {
      const data = await result.json() as JsonRpcResponse;
      return [(data.result as { signature: string }).signature, ""];
    }
    if (result.status === 401) {
      return ["", "Invalid email or password"];
    }
    return ["", "Unknown error"];
  } catch (e) {
    return ["", "something went wrong" + e];
  }
};

interface JsonRpcRequest {
  jsonrpc: string;
  method: string;
  params: unknown;
  id: string;
}

interface JsonRpcResponse {
  jsonrpc: string;
  result: unknown;
  error: string | null;
  id: string;
}

function JsonRpcRequest(
  method: string,
  params: unknown[] = [],
): JsonRpcRequest {
  return {
    jsonrpc: "2.0",
    method,
    params,
    id: Math.floor(Math.random() * 10000).toString(),
  };
}

export { AuthUser, DeauthUser, GenLoginToken };

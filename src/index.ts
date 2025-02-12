import { Buffer } from "node:buffer";

const encoder = new TextEncoder();

function timingSafeEqual(a: string, b: string) {
	const aBytes = encoder.encode(a);
	const bBytes = encoder.encode(b);

	if (aBytes.byteLength !== bBytes.byteLength) {
		return false;
	}

	return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

interface Env {
	USER: string;
	PASSWORD: string;
}

export default {
	async fetch(request, env): Promise<Response> {
		const BASIC_USER = env.USER ?? "admin";
		const BASIC_PASS = env.PASSWORD ?? "admin";

		const url = new URL(request.url);

		const authorization = request.headers.get("Authorization");
		if (!authorization) {
			return new Response("You need to login.", {
				status: 401,
				headers: {
					"WWW-Authenticate": 'Basic realm="my scope", charset="UTF-8"',
				},
			});
		}
		const [scheme, encoded] = authorization.split(" ");

		if (!encoded || scheme !== "Basic") {
			return new Response("Malformed authorization header.", {
				status: 400,
			});
		}

		const credentials = Buffer.from(encoded, "base64").toString();

		const index = credentials.indexOf(":");
		const user = credentials.substring(0, index);
		const pass = credentials.substring(index + 1);

		if (
			!timingSafeEqual(BASIC_USER, user) ||
			!timingSafeEqual(BASIC_PASS, pass)
		) {
			return new Response("You need to login.", {
				status: 401,
				headers: {
					"WWW-Authenticate": 'Basic realm="my scope", charset="UTF-8"',
				},
			});
		}

		return fetch(request);

	},
} satisfies ExportedHandler<Env>;

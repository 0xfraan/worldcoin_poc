import { buffer_decode, buffer_encode } from './utils'
import { webcrypto as crypto}  from 'crypto'
const encoder = new TextEncoder()
const decoder = new TextDecoder()

export const generateKey = async (): Promise<{ key: CryptoKey; iv: Uint8Array }> => {
	return {
		iv: crypto.getRandomValues(new Uint8Array(12)),
		key: await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']),
	}
}

export const exportKey = async (key: CryptoKey): Promise<string> => {
	return buffer_encode(await crypto.subtle.exportKey('raw', key))
}

export const encryptRequest = async (
	key: CryptoKey,
	iv: ArrayBuffer,
	request: string
): Promise<{ payload: string; iv: string }> => {
	return {
		iv: buffer_encode(iv),
		payload: buffer_encode(
			await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(request))
		),
	}
}

export const decryptResponse = async (key: CryptoKey, iv: ArrayBuffer, payload: string): Promise<string> => {
	return decoder.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, buffer_decode(payload)))
}

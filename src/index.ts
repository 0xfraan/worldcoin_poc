import { encodeAction, generateSignal, hashToField } from "./lib/hashing";
import {
  decryptResponse,
  encryptRequest,
  exportKey,
  generateKey,
} from "./lib/crypto";
import {
  DEFAULT_VERIFICATION_LEVEL,
  buffer_decode,
  verification_level_to_credential_types,
} from "./lib/utils";
import { AppErrorCodes, ResponseStatus } from "./types/bridge";
import { ISuccessResult } from "./types/result";
import { CredentialType } from "./types/config";

type BridgeResponse =
  | {
      status: ResponseStatus.Retrieved | ResponseStatus.Initialized;
      response: null;
    }
  | {
      status: ResponseStatus.Completed;
      response: { iv: string; payload: string };
    };

type BridgeResult =
  | ISuccessResult
  | (Omit<ISuccessResult, "verification_level"> & {
      credential_type: CredentialType;
    })
  | { error_code: AppErrorCodes };

interface IVerifyResponse {
  success: boolean;
  code?: string;
  detail?: string;
  attribute?: string | null;
}

const watchChallenge = async (
  request_id: string,
  app_id: `app_${string}`,
  key: CryptoKey,
  action: string,
  signal: string
) => {
  let response: BridgeResponse | null = null;
  let result: BridgeResult | null = null;

  while (!response || response.status !== ResponseStatus.Completed) {
    await new Promise((resolve) => setTimeout(resolve, 5000));

    const res = await fetch(
      `https://bridge.worldcoin.org/response/${request_id}`
    );
    response = (await res.json()) as BridgeResponse;
  }

  result = JSON.parse(
    await decryptResponse(
      key,
      buffer_decode(response.response.iv),
      response.response.payload
    )
  ) as BridgeResult;

  const v = await verifyCloudProof(
    result as ISuccessResult,
    app_id,
    action,
    signal
  );
  console.log(v);
};

const verifyCloudProof = async (
  proof: ISuccessResult,
  app_id: `app_${string}`,
  action: string,
  signal: string
): Promise<IVerifyResponse> => {
  const response = await fetch(
    `https://developer.worldcoin.org/api/v2/verify/${app_id}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ...proof,
        action,
        signal_hash: hashToField(signal ?? "").digest,
      }),
    }
  );
  if (response.ok) {
    return { success: true };
  } else {
    return { success: false, ...(await response.json()) } as IVerifyResponse;
  }
};

const generateChallenge = async () => {
  const app_id = process.env.WORLDCOIN_APPID;

  const action = "emojiprotocol-kyc";
  const action_description = "Unlock lower fees after verifying";

  const signal = "emojiprotocol-kyc";

  const { key, iv } = await generateKey();

  const res = await fetch(`https://bridge.worldcoin.org/request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(
      await encryptRequest(
        key,
        iv,
        JSON.stringify({
          app_id,
          action_description,
          action: encodeAction(action),
          signal: generateSignal(signal).digest,
          credential_types: verification_level_to_credential_types(
            DEFAULT_VERIFICATION_LEVEL
          ),
          verification_level: DEFAULT_VERIFICATION_LEVEL,
        })
      )
    ),
  });

  if (!res.ok) throw new Error("Failed to create client");

  const { request_id } = (await res.json()) as { request_id: string };
  const encoded_key = encodeURIComponent(await exportKey(key));

  watchChallenge(request_id, app_id as `app_${string}`, key, action, signal);
  return `https://worldcoin.org/verify?t=wld&i=${request_id}&k=${encoded_key}`;
};

const url = await generateChallenge();
console.log(url);

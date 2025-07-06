//src/utils/auth.utils.ts
import { v4 as uuidv4 } from "uuid";
import QRCode from "qrcode";
import { BlobServiceClient } from "@azure/storage-blob";
import twilio from "twilio";
import crypto from "crypto";
import { config } from "../config";
import { logger } from "./logger";
import { redisClient } from "../config/redis";

const blobServiceClient = BlobServiceClient.fromConnectionString(
  config.azureStorage.connectionString
);
const containerClient =
  blobServiceClient.getContainerClient("momemilkapp-files");

const twilioClient = twilio(config.twilio.accountSid, config.twilio.authToken);

export const generateQRCode = async (uniqueId: string): Promise<string> => {
  try {
    const qrCodeData = `https://app.momemilk.com/vendor/${uniqueId}`;
    const qrCodeBuffer = await QRCode.toBuffer(qrCodeData, {
      errorCorrectionLevel: "H",
      width: 300,
    });

    const blobName = `qr_codes/${uniqueId}_${Date.now()}.png`;
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
    await blockBlobClient.upload(qrCodeBuffer, qrCodeBuffer.length, {
      blobHTTPHeaders: { blobContentType: "image/png" },
    });

    return blockBlobClient.url;
  } catch (error) {
    logger.error("QR code generation error:", error);
    throw new Error("Failed to generate QR code");
  }
};

export const uploadDocument = async (
  buffer: Buffer,
  originalName: string,
  mimeType: string
): Promise<string> => {
  try {
    const blobName = `documents/${uuidv4()}_${originalName}`;
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
    await blockBlobClient.upload(buffer, buffer.length, {
      blobHTTPHeaders: { blobContentType: mimeType },
    });
    return blockBlobClient.url;
  } catch (error) {
    logger.error("Document upload error:", error);
    throw new Error("Failed to upload document");
  }
};

export const sendOTP = async (mobileNumber: string): Promise<string> => {
  try {
    const rateLimitKey = `rate_limit:otp:${mobileNumber}`;
    const isAllowed = await checkRateLimit(rateLimitKey, 5, 15 * 60 * 1000);
    if (!isAllowed) {
      throw new Error("OTP request limit exceeded");
    }

    const verification = await twilioClient.verify.v2
      .services(config.twilio.verifySid)
      .verifications.create({
        to: mobileNumber,
        channel: "sms",
        locale: "en",
      });
    logger.info(
      `OTP sent to ${mobileNumber} via Verify SID ${config.twilio.verifySid}`
    );
    return verification.sid;
  } catch (error) {
    logger.error(`Failed to send OTP to ${mobileNumber}:`, error);
    throw new Error("Failed to send OTP");
  }
};

export const verifyOTP = async (
  mobileNumber: string,
  otp: string
): Promise<boolean> => {
  try {
    const verificationCheck = await twilioClient.verify.v2
      .services(config.twilio.verifySid)
      .verificationChecks.create({ to: mobileNumber, code: otp });
    return verificationCheck.status === "approved";
  } catch (error) {
    logger.error("OTP verification error:", error);
    return false;
  }
};

export const encryptData = (data: string): string => {
  try {
    // Validate encryption key and IV
    const keyBuffer = Buffer.from(config.encryption.key, "hex");
    const ivBuffer = Buffer.from(config.encryption.iv, "hex");

    if (keyBuffer.length !== 32) {
      throw new Error(
        `Invalid encryption key length: expected 32 bytes, got ${keyBuffer.length} bytes`
      );
    }
    if (ivBuffer.length !== 16) {
      throw new Error(
        `Invalid initialization vector length: expected 16 bytes, got ${ivBuffer.length} bytes`
      );
    }

    const cipher = crypto.createCipheriv("aes-256-cbc", keyBuffer, ivBuffer);
    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
  } catch (error) {
    logger.error("Encryption error:", error);
    throw new Error("Failed to encrypt data");
  }
};

export const decryptData = (encryptedData: string): string => {
  try {
    // Validate encryption key and IV
    const keyBuffer = Buffer.from(config.encryption.key, "hex");
    const ivBuffer = Buffer.from(config.encryption.iv, "hex");

    if (keyBuffer.length !== 32) {
      throw new Error(
        `Invalid encryption key length: expected 32 bytes, got ${keyBuffer.length} bytes`
      );
    }
    if (ivBuffer.length !== 16) {
      throw new Error(
        `Invalid initialization vector length: expected 16 bytes, got ${ivBuffer.length} bytes`
      );
    }

    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      keyBuffer,
      ivBuffer
    );
    let decrypted = decipher.update(encryptedData, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    logger.error("Decryption error:", error);
    throw new Error("Failed to decrypt data");
  }
};

const checkRateLimit = async (
  key: string,
  limit: number,
  windowMs: number
): Promise<boolean> => {
  const count = await redisClient.incr(key);
  if (count === 1) {
    await redisClient.expire(key, windowMs / 1000);
  }
  return count <= limit;
};

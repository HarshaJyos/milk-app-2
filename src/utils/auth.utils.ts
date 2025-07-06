//src/utils/auth.utils.ts
import { randomInt } from "crypto";
import { v4 as uuidv4 } from "uuid";
import QRCode from "qrcode";
import { Twilio } from "twilio";
import { config } from "../config";
import { getContainerClient } from "../config/azureBlob";
import { logger } from "./logger";

// Initialize Twilio client
const twilioClient = new Twilio(
  config.twilio.accountSid,
  config.twilio.authToken
);

// Generate 6-digit OTP (for fallback or manual testing)
export const generateOTP = (): string => {
  return randomInt(100000, 999999).toString();
};

// Encrypt sensitive data (e.g., licenseNumber, taxId)
export const encryptData = (data: string): string => {
  const cipher = require("crypto").createCipheriv(
    "aes-256-cbc",
    Buffer.from(config.encryption.key),
    Buffer.from(config.encryption.iv)
  );
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
};

// Decrypt sensitive data
export const decryptData = (encryptedData: string): string => {
  const decipher = require("crypto").createDecipheriv(
    "aes-256-cbc",
    Buffer.from(config.encryption.key),
    Buffer.from(config.encryption.iv)
  );
  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
};

// Generate QR code for vendor
export const generateQRCode = async (uniqueId: string): Promise<string> => {
  try {
    const url = `https://api.milkapp.com/vendors/link?uniqueId=${uniqueId}`;
    const qrCodeData = await QRCode.toDataURL(url);
    const containerClient = await getContainerClient();
    const blobName = `qr_codes/${uniqueId}_${Date.now()}.png`;
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);

    const buffer = Buffer.from(qrCodeData.split(",")[1], "base64");
    await blockBlobClient.upload(buffer, buffer.length, {
      blobHTTPHeaders: { blobContentType: "image/png" },
    });

    const qrCodeUrl = blockBlobClient.url;
    logger.info(`QR code generated for uniqueId: ${uniqueId}`);
    return qrCodeUrl;
  } catch (error) {
    logger.error("QR code generation error:", error);
    throw new Error("Failed to generate QR code");
  }
};

// Upload document to Azure Blob Storage
export const uploadDocument = async (
  file: Buffer,
  fileName: string,
  mimeType: string
): Promise<string> => {
  try {
    const containerClient = await getContainerClient();
    const blobName = `documents/${uuidv4()}_${fileName}`;
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);

    await blockBlobClient.upload(file, file.length, {
      blobHTTPHeaders: { blobContentType: mimeType },
    });

    logger.info(`Document uploaded: ${blobName}`);
    return blockBlobClient.url;
  } catch (error) {
    logger.error("Document upload error:", error);
    throw new Error("Failed to upload document");
  }
};

// Send OTP via Twilio Verify
export const sendOTP = async (mobileNumber: string): Promise<string> => {
  try {
    const verification = await twilioClient.verify.v2
      .services(config.twilio.verifySid)
      .verifications.create({
        to: mobileNumber,
        channel: "sms",
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

// Verify OTP via Twilio Verify
export const verifyOTP = async (
  mobileNumber: string,
  otp: string
): Promise<boolean> => {
  try {
    const verificationCheck = await twilioClient.verify.v2
      .services(config.twilio.verifySid)
      .verificationChecks.create({
        to: mobileNumber,
        code: otp,
      });
    const isValid = verificationCheck.status === "approved";
    logger.info(
      `OTP verification for ${mobileNumber}: ${isValid ? "success" : "failed"}`
    );
    return isValid;
  } catch (error) {
    logger.error(`Failed to verify OTP for ${mobileNumber}:`, error);
    throw new Error("Failed to verify OTP");
  }
};

//src/config/index.ts
import dotenv from "dotenv";

dotenv.config();

export const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || "development",
  mongoUri: process.env.MONGO_URI || "mongodb://localhost:27017/milk-app",
  redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
  azureStorage: {
    connectionString: process.env.AZURE_STORAGE_CONNECTION_STRING || "",
    containerName: process.env.AZURE_CONTAINER_NAME || "milk-app-files",
  },
  logLevel: process.env.LOG_LEVEL || "info",
  jwt: {
    secret: process.env.JWT_SECRET || "your_jwt_secret_key",
    expiresIn: "24h" as const,
    adminExpiresIn: "8h" as const,
  },
  encryption: {
    key: process.env.ENCRYPTION_KEY || "32_character_encryption_key_here",
    iv: process.env.ENCRYPTION_IV || "16_char_iv_here",
  },
  twilio: {
    accountSid: process.env.TWILIO_ACCOUNT_SID || "",
    authToken: process.env.TWILIO_AUTH_TOKEN || "",
    verifySid: process.env.TWILIO_VERIFY_SID || "", // Added Verify SID
  },
};

//src/config/database.ts
import mongoose from "mongoose";
import { config } from "./index";
import { logger } from "../utils/logger";

export const connectMongoDB = async (): Promise<void> => {
  try {
    await mongoose.connect(config.mongoUri, {
      autoIndex: true,
      serverSelectionTimeoutMS: 5000,
    });
    logger.info("MongoDB connected successfully");
  } catch (error) {
    logger.error("MongoDB connection error:", error);
    process.exit(1);
  }
};

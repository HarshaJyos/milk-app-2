//src/config/redis.ts
import { createClient } from "redis";
import { config } from "./index";
import { logger } from "../utils/logger";

const redisClient = createClient({
  url: config.redisUrl,
});

redisClient.on("error", (err) => {
  logger.error("Redis connection error:", err);
});

redisClient.on("connect", () => {
  logger.info("Redis connected successfully");
});

export const connectRedis = async (): Promise<void> => {
  await redisClient.connect();
};

export { redisClient };

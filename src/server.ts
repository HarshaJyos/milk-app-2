//src/server.ts
import app from "./app";
import { connectMongoDB } from "./config/database";
import { connectRedis } from "./config/redis";
import { getContainerClient } from "./config/azureBlob";
import { config } from "./config";
import { logger } from "./utils/logger";

const startServer = async () => {
  try {
    await connectMongoDB();
    await connectRedis();
    await getContainerClient();

    app.listen(config.port, () => {
      logger.info(`Server running on port ${config.port}`);
    });
  } catch (error) {
    logger.error("Failed to start server:", error);
    process.exit(1);
  }
};

startServer();

//src/config/azureBlob.ts
import { BlobServiceClient } from "@azure/storage-blob";
import { config } from "./index";
import { logger } from "../utils/logger";

const blobServiceClient = BlobServiceClient.fromConnectionString(
  config.azureStorage.connectionString
);

export const getContainerClient = async () => {
  try {
    const containerClient = blobServiceClient.getContainerClient(
      config.azureStorage.containerName
    );
    await containerClient.createIfNotExists();
    logger.info("Azure Blob Storage container initialized");
    return containerClient;
  } catch (error) {
    logger.error("Azure Blob Storage initialization error:", error);
    throw error;
  }
};

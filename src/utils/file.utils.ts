import { v4 as uuidv4 } from "uuid";
import { BlobServiceClient, ContainerClient } from "@azure/storage-blob";
import { config } from "../config";
import { logger } from "./logger";

const blobServiceClient = BlobServiceClient.fromConnectionString(
  config.azureStorage.connectionString
);
const containerClient: ContainerClient =
  blobServiceClient.getContainerClient("momemilkapp-files");

export const uploadImages = async (
  files: Express.Multer.File[]
): Promise<string[]> => {
  try {
    // Verify container exists
    const containerExists = await containerClient.exists();
    if (!containerExists) {
      logger.error("Azure container 'momemilkapp-files' does not exist");
      throw new Error("Storage container not found");
    }

    // Validate files
    if (!files || files.length === 0) {
      logger.error("No files provided for upload", {
        fileCount: files?.length,
      });
      throw new Error("No images provided");
    }

    const allowedTypes = ["image/png", "image/jpeg"];
    const uploadPromises = files.map(async (file, index) => {
      logger.debug(
        `Processing file ${index + 1}/${files.length}: ${file.originalname}`,
        {
          mimetype: file.mimetype,
          size: file.size,
          bufferLength: file.buffer?.length,
        }
      );
      if (!allowedTypes.includes(file.mimetype)) {
        logger.warn(
          `Invalid file type for ${file.originalname}: ${file.mimetype}`
        );
        throw new Error(`Invalid file type for ${file.originalname}`);
      }

      if (!file.buffer || file.buffer.length === 0) {
        logger.error(`Empty or invalid buffer for ${file.originalname}`);
        throw new Error(`Invalid file buffer for ${file.originalname}`);
      }

      const blobName = `products/images/${uuidv4()}_${file.originalname}`;
      logger.debug(
        `Uploading image to Azure: ${blobName}, MIME: ${file.mimetype}, Size: ${file.size} bytes`
      );
      const blockBlobClient = containerClient.getBlockBlobClient(blobName);
      await blockBlobClient.upload(file.buffer, file.buffer.length, {
        blobHTTPHeaders: { blobContentType: file.mimetype },
      });
      logger.info(`Successfully uploaded image to Azure: ${blobName}`);
      return blockBlobClient.url;
    });

    const urls = await Promise.all(uploadPromises);
    logger.info(`Uploaded ${urls.length} images successfully`);
    return urls;
  } catch (error: any) {
    logger.error("Image upload error:", {
      message: error.message,
      stack: error.stack,
      files: files.map((f) => ({
        originalname: f.originalname,
        mimetype: f.mimetype,
        size: f.size,
      })),
    });
    throw new Error(`Failed to upload images: ${error.message}`);
  }
};

export const deleteImages = async (imageUrls: string[]): Promise<void> => {
  try {
    if (!imageUrls || imageUrls.length === 0) {
      logger.warn("No image URLs provided for deletion");
      return;
    }

    const deletePromises = imageUrls.map(async (url) => {
      const blobName = url.split("momemilkapp-files/")[1];
      if (!blobName) {
        logger.warn(`Invalid blob URL: ${url}`);
        throw new Error(`Invalid blob URL: ${url}`);
      }
      const blockBlobClient = containerClient.getBlockBlobClient(blobName);
      await blockBlobClient.deleteIfExists();
      logger.info(`Successfully deleted image from Azure: ${blobName}`);
    });

    await Promise.all(deletePromises);
  } catch (error: any) {
    logger.error("Image deletion error:", {
      message: error.message,
      stack: error.stack,
      imageUrls,
    });
    throw new Error(`Failed to delete images: ${error.message}`);
  }
};

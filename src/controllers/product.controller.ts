import { Request, Response, NextFunction } from "express";
import { StatusCodes } from "http-status-codes";
import { logger } from "../utils/logger";
import { ProductModel, VendorModel, AuditLogModel } from "../models";
import { ProductZodSchema } from "../models";
import {
  uploadImages,
  deleteImages as deleteImagesUtil,
} from "../utils/file.utils";

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    role: "customer" | "vendor" | "admin" | "super_admin";
  };
}

// Create Product
export const createProduct = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || req.user.role !== "vendor") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only vendors can create products",
      });
      return;
    }

    const vendor = await VendorModel.findById(req.user.id);
    if (!vendor || vendor.status !== "approved") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Vendor not found or not approved",
      });
      return;
    }

    // Log raw request body and files for debugging
    logger.debug("Raw request body:", req.body);
    logger.debug("Raw files:", req.files);

    // Parse and normalize request body
    const parsedBody = { ...req.body };

    // Handle fields that might be arrays
    const normalizeField = (value: any, fieldName: string): any => {
      if (Array.isArray(value)) {
        if (value.length === 0) {
          res.status(StatusCodes.BAD_REQUEST).json({
            success: false,
            error: `Field ${fieldName} is an empty array`,
          });
          return null;
        }
        return value[0];
      }
      return value;
    };

    // Normalize fields that should be strings
    ["name", "category", "sku", "unit", "description", "variant"].forEach(
      (field) => {
        if (parsedBody[field]) {
          const normalized = normalizeField(parsedBody[field], field);
          if (normalized === null) throw new Error(`Invalid ${field}`);
          parsedBody[field] = normalized;
        }
      }
    );

    // Parse JSON fields and handle arrays
    const jsonFields = ["price", "stock", "bulkDiscounts", "promotions"];
    for (const field of jsonFields) {
      if (parsedBody[field]) {
        const normalized = normalizeField(parsedBody[field], field);
        if (normalized === null) throw new Error(`Invalid ${field}`);
        if (typeof normalized === "string") {
          logger.debug(`Raw ${field} value:`, normalized);
          if (normalized.trim() === "") {
            parsedBody[field] =
              field === "promotions" || field === "bulkDiscounts" ? [] : null;
            continue;
          }
          try {
            parsedBody[field] = JSON.parse(normalized);
          } catch (error) {
            logger.error(`JSON parse error for ${field}:`, error);
            res.status(StatusCodes.BAD_REQUEST).json({
              success: false,
              error: `Invalid JSON format for ${field} field: ${normalized}`,
            });
            return;
          }
        } else {
          parsedBody[field] = normalized;
        }
      }
    }

    // Trim string fields
    const trimmedBody = Object.fromEntries(
      Object.entries(parsedBody).map(([key, value]) => [
        key,
        typeof value === "string" ? value.trim() : value,
      ])
    );

    const parsed = ProductZodSchema.parse({
      ...trimmedBody,
      vendorId: req.user.id,
    });

    const existingProduct = await ProductModel.findOne({ sku: parsed.sku });
    if (existingProduct) {
      res.status(StatusCodes.CONFLICT).json({
        success: false,
        error: "SKU already exists",
      });
      return;
    }

    // Handle image uploads
    const files = req.files as
      | { [fieldname: string]: Express.Multer.File[] }
      | undefined;
    const images: string[] = [];
    if (files && files.images && files.images.length > 0) {
      try {
        images.push(...(await uploadImages(files.images)));
      } catch (error: any) {
        logger.error("Image upload error in createProduct:", {
          message: error.message,
          stack: error.stack,
          files: files.images.map((f) => ({
            originalname: f.originalname,
            mimetype: f.mimetype,
            size: f.size,
          })),
        });
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: `Image upload failed: ${error.message}`,
        });
        return;
      }
    } else if (files) {
      logger.warn(
        "No images provided in createProduct request or incorrect fieldname",
        {
          filesExist: !!files,
          imagesFieldExist: files ? !!files.images : false,
          fileDetails: files ? Object.keys(files) : [],
          allFiles: files ? JSON.stringify(files) : null,
        }
      );
    }

    const product = new ProductModel({
      ...parsed,
      images,
      available: true,
      schemaVersion: 1,
    });
    await product.save();

    await AuditLogModel.create({
      action: "product_updated",
      performedBy: req.user.id,
      targetId: product._id,
      targetType: "product",
      details: {
        after: product.toObject(),
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      },
      schemaVersion: 1,
    });

    res.status(StatusCodes.CREATED).json({
      success: true,
      data: {
        product: {
          _id: product._id,
          name: product.name,
          sku: product.sku,
          images,
        },
      },
    });
  } catch (error: any) {
    logger.error("Create product error:", {
      message: error.message,
      stack: error.stack,
      body: req.body,
      files: req.files,
    });
    next(error);
  }
};

// Update Product
export const updateProduct = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || req.user.role !== "vendor") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only vendors can update products",
      });
      return;
    }

    const vendor = await VendorModel.findById(req.user.id);
    if (!vendor || vendor.status !== "approved") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Vendor not found or not approved",
      });
      return;
    }

    const { productId } = req.params;
    const product = await ProductModel.findOne({
      _id: productId,
      vendorId: req.user.id,
    });
    if (!product) {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Product not found or not owned by vendor",
      });
      return;
    }

    // Log raw request body and files for debugging
    logger.debug("Raw request body:", req.body);
    logger.debug("Raw files:", req.files);

    // Parse and normalize request body
    const parsedBody = { ...req.body };

    // Handle fields that might be arrays
    const normalizeField = (value: any, fieldName: string): any => {
      if (Array.isArray(value)) {
        if (value.length === 0) {
          res.status(StatusCodes.BAD_REQUEST).json({
            success: false,
            error: `Field ${fieldName} is an empty array`,
          });
          return null;
        }
        return value[0];
      }
      return value;
    };

    // Normalize fields that should be strings
    ["name", "category", "sku", "unit", "description", "variant"].forEach(
      (field) => {
        if (parsedBody[field]) {
          const normalized = normalizeField(parsedBody[field], field);
          if (normalized === null) throw new Error(`Invalid ${field}`);
          parsedBody[field] = normalized;
        }
      }
    );

    // Parse JSON fields and handle arrays
    const jsonFields = ["price", "stock", "bulkDiscounts", "promotions"];
    for (const field of jsonFields) {
      if (parsedBody[field]) {
        const normalized = normalizeField(parsedBody[field], field);
        if (normalized === null) throw new Error(`Invalid ${field}`);
        if (typeof normalized === "string") {
          logger.debug(`Raw ${field} value:`, normalized);
          if (normalized.trim() === "") {
            parsedBody[field] =
              field === "promotions" || field === "bulkDiscounts" ? [] : null;
            continue;
          }
          try {
            parsedBody[field] = JSON.parse(normalized);
          } catch (error) {
            logger.error(`JSON parse error for ${field}:`, error);
            res.status(StatusCodes.BAD_REQUEST).json({
              success: false,
              error: `Invalid JSON format for ${field} field: ${normalized}`,
            });
            return;
          }
        } else {
          parsedBody[field] = normalized;
        }
      }
    }

    // Handle image deletion
    let imagesToDelete: string[] = [];
    if (parsedBody.deleteImages) {
      try {
        imagesToDelete = Array.isArray(parsedBody.deleteImages)
          ? parsedBody.deleteImages
          : JSON.parse(parsedBody.deleteImages);
        if (
          !imagesToDelete.every(
            (url: string) =>
              typeof url === "string" && url.includes("momemilkapp-files")
          )
        ) {
          throw new Error("Invalid image URLs for deletion");
        }
      } catch (error) {
        logger.error("Invalid deleteImages field:", error);
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: "Invalid format for deleteImages field",
        });
        return;
      }

      try {
        await deleteImagesUtil(imagesToDelete);
      } catch (error: any) {
        logger.error("Image deletion error in updateProduct:", error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
          success: false,
          error: `Image deletion failed: ${error.message}`,
        });
        return;
      }
    }

    // Trim string fields
    const trimmedBody = Object.fromEntries(
      Object.entries(parsedBody).map(([key, value]) => [
        key,
        typeof value === "string" ? value.trim() : value,
      ])
    );

    // Remove deleteImages from the body before parsing since it's not part of the schema
    const { deleteImages, ...bodyWithoutDeleteImages } = trimmedBody;
    const parsed = ProductZodSchema.partial().parse(bodyWithoutDeleteImages);

    // Handle image uploads
    const files = req.files as
      | { [fieldname: string]: Express.Multer.File[] }
      | undefined;
    let newImages: string[] = [];
    if (files && files.images && files.images.length > 0) {
      try {
        newImages = await uploadImages(files.images);
      } catch (error: any) {
        logger.error("Image upload error in updateProduct:", {
          message: error.message,
          stack: error.stack,
          files: files.images.map((f) => ({
            originalname: f.originalname,
            mimetype: f.mimetype,
            size: f.size,
          })),
        });
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: `Image upload failed: ${error.message}`,
        });
        return;
      }
    } else if (files) {
      logger.warn(
        "No images provided in updateProduct request or incorrect fieldname",
        {
          filesExist: !!files,
          imagesFieldExist: files ? !!files.images : false,
          fileDetails: files ? Object.keys(files) : [],
          allFiles: files ? JSON.stringify(files) : null,
        }
      );
    }

    // Merge existing and new images, excluding deleted images
    const currentImages = product.images || [];
    const updatedImages =
      imagesToDelete.length > 0
        ? currentImages.filter((url) => !imagesToDelete.includes(url))
        : currentImages;
    updatedImages.push(...newImages);

    const updatedProduct = {
      ...product.toObject(),
      ...parsed,
      images: updatedImages,
    };

    await ProductModel.updateOne({ _id: productId }, { $set: updatedProduct });

    await AuditLogModel.create({
      action: "product_updated",
      performedBy: req.user.id,
      targetId: product._id,
      targetType: "product",
      details: {
        before: product.toObject(),
        after: updatedProduct,
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { message: "Product updated successfully", images: updatedImages },
    });
  } catch (error: any) {
    logger.error("Update product error:", {
      message: error.message,
      stack: error.stack,
      body: req.body,
      files: req.files,
    });
    next(error);
  }
};

// Delete Product
export const deleteProduct = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || req.user.role !== "vendor") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only vendors can delete products",
      });
      return;
    }

    const vendor = await VendorModel.findById(req.user.id);
    if (!vendor || vendor.status !== "approved") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Vendor not found or not approved",
      });
      return;
    }

    const { productId } = req.params;
    const product = await ProductModel.findOne({
      _id: productId,
      vendorId: req.user.id,
    });
    if (!product) {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Product not found or not owned by vendor",
      });
      return;
    }

    // Delete images from Azure
    if (product.images && product.images.length > 0) {
      try {
        await deleteImagesUtil(product.images);
      } catch (error: any) {
        logger.error("Image deletion error in deleteProduct:", error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
          success: false,
          error: `Image deletion failed: ${error.message}`,
        });
        return;
      }
    }

    await ProductModel.deleteOne({ _id: productId });

    await AuditLogModel.create({
      action: "product_updated",
      performedBy: req.user.id,
      targetId: product._id,
      targetType: "product",
      details: {
        action: "deleted",
        before: product.toObject(),
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { message: "Product deleted successfully" },
    });
  } catch (error: any) {
    logger.error("Delete product error:", {
      message: error.message,
      stack: error.stack,
    });
    next(error);
  }
};

// List Vendor's Products
export const listVendorProducts = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || req.user.role !== "vendor") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only vendors can view their products",
      });
      return;
    }

    const vendor = await VendorModel.findById(req.user.id);
    if (!vendor || vendor.status !== "approved") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Vendor not found or not approved",
      });
      return;
    }

    const { category, page = 1, limit = 10 } = req.query;
    const query: any = { vendorId: req.user.id };
    if (category) query.category = category;

    const products = await ProductModel.find(query)
      .select("name category sku price stock available images")
      .skip((Number(page) - 1) * Number(limit))
      .limit(Number(limit))
      .lean();

    const total = await ProductModel.countDocuments(query);

    await AuditLogModel.create({
      action: "product_updated",
      performedBy: req.user.id,
      targetId: req.user.id,
      targetType: "vendor",
      details: {
        action: "viewed_products",
        query,
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { products, total, page: Number(page), limit: Number(limit) },
    });
  } catch (error: any) {
    logger.error("List vendor products error:", {
      message: error.message,
      stack: error.stack,
    });
    next(error);
  }
};

// Get Vendor Details and Available Products
export const getVendorDetails = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || req.user.role !== "customer") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only customers can view vendor details",
      });
      return;
    }

    const { vendorId } = req.params;
    const vendor = await VendorModel.findById(vendorId).select(
      "name email contact status"
    );
    if (!vendor) {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Vendor not found",
      });
      return;
    }

    const products = await ProductModel.find({
      vendorId,
      available: true,
    }).select("name category sku price stock images");

    await AuditLogModel.create({
      action: "vendor_viewed",
      performedBy: req.user.id,
      targetId: vendorId,
      targetType: "vendor",
      details: {
        action: "viewed_vendor_details",
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: {
        vendor,
        products,
      },
    });
  } catch (error: any) {
    logger.error("Get vendor details error:", {
      message: error.message,
      stack: error.stack,
    });
    next(error);
  }
};

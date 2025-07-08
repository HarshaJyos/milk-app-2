import { Router } from "express";
import {
  createProduct,
  updateProduct,
  deleteProduct,
  listVendorProducts,
  getVendorDetails,
} from "../controllers/product.controller";
import { authenticate, authorize } from "../middleware/auth.middleware";
import { rateLimit } from "../middleware/rateLimit";
import multer from "multer";
import { logger } from "../utils/logger";

const router = Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 5, // Max 5 images per product
  },
  fileFilter: (_req, file, cb) => {
    const allowedTypes = ["image/png", "image/jpeg"];
    if (allowedTypes.includes(file.mimetype)) {
      logger.debug(
        `Multer accepted file: ${file.originalname}, MIME: ${file.mimetype}, Size: ${file.size} bytes, Fieldname: ${file.fieldname}`
      );
      cb(null, true);
    } else {
      logger.warn(
        `Multer rejected file: ${file.originalname}, MIME: ${file.mimetype}, Fieldname: ${file.fieldname}`
      );
      cb(new multer.MulterError("LIMIT_UNEXPECTED_FILE", file.fieldname));
    }
  },
});

// Product Management Routes
router.post(
  "/create",
  authenticate,
  authorize(["vendor"]),
  rateLimit,
  (req, res, next) => {
    logger.debug("Incoming request to /create before Multer", {
      headers: req.headers,
      body: req.body,
      files: req.files, // Should be undefined before Multer
    });
    upload.fields([{ name: "images", maxCount: 5 }])(req, res, (err) => {
      if (err) return next(err);
      logger.debug("Incoming request to /create after Multer", {
        headers: req.headers,
        body: req.body,
        files: req.files, // Should contain files under "images"
      });
      next();
    });
  },
  createProduct
);
router.patch(
  "/:productId",
  authenticate,
  authorize(["vendor"]),
  rateLimit,
  (req, res, next) => {
    logger.debug("Incoming request to /:productId before Multer", {
      headers: req.headers,
      body: req.body,
      files: req.files,
    });
    upload.fields([{ name: "images", maxCount: 5 }])(req, res, (err) => {
      if (err) return next(err);
      logger.debug("Incoming request to /:productId after Multer", {
        headers: req.headers,
        body: req.body,
        files: req.files,
      });
      next();
    });
  },
  updateProduct
);
router.delete(
  "/:productId",
  authenticate,
  authorize(["vendor"]),
  rateLimit,
  deleteProduct
);
router.get(
  "/",
  authenticate,
  authorize(["vendor"]),
  rateLimit,
  listVendorProducts
);
router.get(
  "/vendor/:vendorId",
  authenticate,
  authorize(["customer"]),
  rateLimit,
  getVendorDetails
);
router.use((err: any, req: any, res: any, next: any) => {
  logger.error("Product route error:", {
    message: err.message,
    stack: err.stack,
    files: req.files,
    headers: req.headers,
  });
  if (err instanceof multer.MulterError) {
    res.status(400).json({
      success: false,
      error: `File upload error: ${err.message} (${err.field})`,
    });
  } else if (err.name === "ZodError") {
    res.status(400).json({
      success: false,
      error: "Validation failed",
      details: err.issues.map((issue: any) => ({
        path: issue.path.join("."),
        message: issue.message,
      })),
    });
  } else {
    res.status(500).json({
      success: false,
      error: `Internal server error: ${err.message}`,
    });
  }
});

export default router;

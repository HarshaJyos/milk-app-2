import { Router } from "express";
import {
  customerRegister,
  customerVerifyOTP,
  customerLogin,
  vendorRegister,
  vendorVerifyOTP,
  vendorLogin,
  vendorVerifyLoginOTP,
  adminLogin,
  logout,
  refreshToken,
  adminRegister,
  adminVerify2FA,
  adminToggle2FA,
} from "../controllers/auth.controller";
import { authenticate, authorize } from "../middleware/auth.middleware";
import multer from "multer";
import { logger } from "../utils/logger";

const router = Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 3, // Max 3 files for vendor documents
  },
});

// Customer Routes
router.post("/customer/register", customerRegister);
router.post("/customer/verify-otp", customerVerifyOTP);
router.post("/customer/login", customerLogin);

// Vendor Routes
router.post(
  "/vendor/register",
  upload.fields([
    { name: "license", maxCount: 1 },
    { name: "tax", maxCount: 1 },
    { name: "identity", maxCount: 1 },
  ]),
  vendorRegister
);
router.post("/vendor/verify-otp", vendorVerifyOTP);
router.post("/vendor/login", vendorLogin);
router.post("/vendor/verify-login-otp", vendorVerifyLoginOTP);

// Admin Routes
router.post("/admin/register", adminRegister);
router.post("/admin/verify-2fa", adminVerify2FA);
router.post("/admin/login", adminLogin);
router.post(
  "/admin/toggle-2fa",
  authenticate,
  authorize(["super_admin", "admin"]),
  adminToggle2FA
);

// Protected Routes
router.post("/logout", authenticate, logout);
router.post("/refresh-token", authenticate, refreshToken);

router.use((err: any, req: any, res: any, next: any) => {
  logger.error("Route error:", err);
  if (err instanceof multer.MulterError) {
    res.status(400).json({
      success: false,
      error: `File upload error: ${err.message}`,
    });
  } else {
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

export default router;

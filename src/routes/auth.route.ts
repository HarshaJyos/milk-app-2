import { Router } from "express";
import multer from "multer";
import {
  customerRegister,
  customerVerifyOTP,
  customerLogin,
  vendorRegister,
  vendorVerifyOTP,
  vendorLogin,
  adminRegister,
  adminLogin,
  forgotPassword,
  resetPassword,
  logout,
} from "../controllers/auth.controller";
import {
  authenticateJWT,
  restrictTo,
  rateLimit,
} from "../middleware/auth.middleware";

const router = Router();
const upload = multer({ storage: multer.memoryStorage() });

// Customer Routes
router.post(
  "/customer/register",
  rateLimit("otp", 5, 5 * 60 * 1000),
  customerRegister
);
router.post(
  "/customer/verify-otp",
  rateLimit("otp", 5, 5 * 60 * 1000),
  customerVerifyOTP
);
router.post(
  "/customer/login",
  rateLimit("login", 5, 5 * 60 * 1000),
  customerLogin
);

// Vendor Routes
router.post(
  "/vendor/register",
  upload.fields([
    { name: "license", maxCount: 1 },
    { name: "tax", maxCount: 1 },
    { name: "identity", maxCount: 1 },
  ]),
  rateLimit("otp", 5, 5 * 60 * 1000),
  vendorRegister
);
router.post(
  "/vendor/verify-otp",
  rateLimit("otp", 5, 5 * 60 * 1000),
  vendorVerifyOTP
);
router.post("/vendor/login", rateLimit("login", 5, 5 * 60 * 1000), vendorLogin);

// Admin Routes
router.post(
  "/admin/register",
  authenticateJWT,
  restrictTo("super_admin"),
  adminRegister
);
router.post("/admin/login", rateLimit("login", 5, 5 * 60 * 1000), adminLogin);
router.post(
  "/admin/forgot-password",
  rateLimit("otp", 5, 5 * 60 * 1000),
  forgotPassword
);
router.post(
  "/admin/reset-password",
  rateLimit("otp", 5, 5 * 60 * 1000),
  resetPassword
);

// Logout Route
router.post("/logout", authenticateJWT, logout);

export default router;

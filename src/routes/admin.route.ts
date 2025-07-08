// src/routes/admin.route.ts
import { Router } from "express";
import {
  approveVendor,
  rejectVendor,
  listVendors,
  listCustomers,
  listAdmins,
  listProducts,
} from "../controllers/admin.controller";
import { authenticate, authorize } from "../middleware/auth.middleware";
import { rateLimit } from "../middleware/rateLimit";
import { logger } from "../utils/logger";

const router = Router();

// Admin Vendor Management Routes
router.patch(
  "/vendors/:vendorId/approve",
  authenticate,
  authorize(["super_admin"]),
  rateLimit,
  approveVendor
);
router.patch(
  "/vendors/:vendorId/reject",
  authenticate,
  authorize(["super_admin"]),
  rateLimit,
  rejectVendor
);
router.get(
  "/vendors",
  authenticate,
  authorize(["super_admin", "support"]),
  rateLimit,
  listVendors
);

// Admin Customer Management Routes
router.get(
  "/customers",
  authenticate,
  authorize(["super_admin", "support"]),
  rateLimit,
  listCustomers
);

// Admin Management Routes
router.get(
  "/admins",
  authenticate,
  authorize(["super_admin"]),
  rateLimit,
  listAdmins
);

// Admin Product Viewing Routes
router.get(
  "/products",
  authenticate,
  authorize(["super_admin", "support"]),
  rateLimit,
  listProducts
);

router.use((err: any, req: any, res: any, next: any) => {
  logger.error("Admin route error:", err);
  res.status(500).json({
    success: false,
    error: "Internal server error",
  });
});

export default router;

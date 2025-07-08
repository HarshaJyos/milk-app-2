// src/controllers/admin.controller.ts
import { Request, Response, NextFunction } from "express";
import { StatusCodes } from "http-status-codes";
import { logger } from "../utils/logger";
import {
  VendorModel,
  CustomerModel,
  AdminModel,
  ProductModel,
  AuditLogModel,
  NotificationModel,
} from "../models";

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    role: "customer" | "vendor" | "admin" | "super_admin";
  };
}

// Approve Vendor
export const approveVendor = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || !["super_admin"].includes(req.user.role)) {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only super admins can approve vendors",
      });
      return;
    }

    const { vendorId } = req.params;
    const vendor = await VendorModel.findById(vendorId);
    if (!vendor) {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Vendor not found",
      });
      return;
    }

    if (vendor.status === "approved") {
      res.status(StatusCodes.BAD_REQUEST).json({
        success: false,
        error: "Vendor already approved",
      });
      return;
    }

    vendor.status = "approved";
    vendor.verification.status = "verified";
    vendor.verification.documents = vendor.verification.documents?.map(
      (doc) => ({
        ...doc,
        verifiedAt: new Date(),
      })
    );
    await vendor.save();

    await NotificationModel.create({
      recipientId: vendor._id,
      recipientType: "vendor",
      type: "vendor_verification",
      message: {
        title: "Vendor Approval",
        body: "Your account has been approved by the admin.",
      },
      channel: ["email", "in_app"],
      status: "sent",
      priority: "high",
      schemaVersion: 1,
    });

    await AuditLogModel.create({
      action: "vendor_approved",
      performedBy: req.user.id,
      targetId: vendor._id,
      targetType: "vendor",
      details: {
        before: {
          status: "pending",
          verificationStatus: vendor.verification.status,
        },
        after: { status: "approved", verificationStatus: "verified" },
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { message: "Vendor approved successfully" },
    });
  } catch (error) {
    logger.error("Vendor approval error:", error);
    next(error);
  }
};

// Reject Vendor
export const rejectVendor = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || !["super_admin"].includes(req.user.role)) {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only super admins can reject vendors",
      });
      return;
    }

    const { vendorId } = req.params;
    const { reason } = req.body;

    const vendor = await VendorModel.findById(vendorId);
    if (!vendor) {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Vendor not found",
      });
      return;
    }

    if (vendor.verification.status === "rejected") {
      res.status(StatusCodes.BAD_REQUEST).json({
        success: false,
        error: "Vendor already rejected",
      });
      return;
    }

    vendor.verification.status = "rejected";
    await vendor.save();

    await NotificationModel.create({
      recipientId: vendor._id,
      recipientType: "vendor",
      type: "vendor_verification",
      message: {
        title: "Vendor Rejection",
        body: `Your account was rejected. Reason: ${reason || "Not specified"}`,
      },
      channel: ["email", "in_app"],
      status: "sent",
      priority: "high",
      schemaVersion: 1,
    });

    await AuditLogModel.create({
      action: "vendor_updated",
      performedBy: req.user.id,
      targetId: vendor._id,
      targetType: "vendor",
      details: {
        before: { verificationStatus: vendor.verification.status },
        after: { verificationStatus: "rejected", reason },
        ipAddress: req.ip,
        userAgent: req.get("User-Agent"),
      },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { message: "Vendor rejected successfully" },
    });
  } catch (error) {
    logger.error("Vendor rejection error:", error);
    next(error);
  }
};

// List All Vendors
export const listVendors = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || !["super_admin", "support"].includes(req.user.role)) {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Insufficient permissions",
      });
      return;
    }

    const { status, page = 1, limit = 10 } = req.query;
    const query: any = {};
    if (status) query.status = status;

    const vendors = await VendorModel.find(query)
      .select("name email mobileNumber status shop verification metadata")
      .skip((Number(page) - 1) * Number(limit))
      .limit(Number(limit))
      .lean();

    const total = await VendorModel.countDocuments(query);

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: req.user.id,
      targetId: req.user.id,
      targetType: "admin",
      details: { action: "viewed_vendors", query },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { vendors, total, page: Number(page), limit: Number(limit) },
    });
  } catch (error) {
    logger.error("List vendors error:", error);
    next(error);
  }
};

// List All Customers
export const listCustomers = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || !["super_admin", "support"].includes(req.user.role)) {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Insufficient permissions",
      });
      return;
    }

    const { status, page = 1, limit = 10 } = req.query;
    const query: any = {};
    if (status) query.status = status;

    const customers = await CustomerModel.find(query)
      .select("name email mobileNumber status address metadata")
      .skip((Number(page) - 1) * Number(limit))
      .limit(Number(limit))
      .lean();

    const total = await CustomerModel.countDocuments(query);

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: req.user.id,
      targetId: req.user.id,
      targetType: "admin",
      details: { action: "viewed_customers", query },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { customers, total, page: Number(page), limit: Number(limit) },
    });
  } catch (error) {
    logger.error("List customers error:", error);
    next(error);
  }
};

// List All Admins
export const listAdmins = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || req.user.role !== "super_admin") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only super admins can view admin list",
      });
      return;
    }

    const { status, page = 1, limit = 10 } = req.query;
    const query: any = {};
    if (status) query.status = status;

    const admins = await AdminModel.find(query)
      .select("email name role status lastLogin")
      .skip((Number(page) - 1) * Number(limit))
      .limit(Number(limit))
      .lean();

    const total = await AdminModel.countDocuments(query);

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: req.user.id,
      targetId: req.user.id,
      targetType: "admin",
      details: { action: "viewed_admins", query },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { admins, total, page: Number(page), limit: Number(limit) },
    });
  } catch (error) {
    logger.error("List admins error:", error);
    next(error);
  }
};

// List All Products
export const listProducts = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || !["super_admin", "support"].includes(req.user.role)) {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Insufficient permissions",
      });
      return;
    }

    const { vendorId, category, page = 1, limit = 10 } = req.query;
    const query: any = {};
    if (vendorId) query.vendorId = vendorId;
    if (category) query.category = category;

    const products = await ProductModel.find(query)
      .select("name category sku price stock available vendorId")
      .populate("vendorId", "name shop.name")
      .skip((Number(page) - 1) * Number(limit))
      .limit(Number(limit))
      .lean();

    const total = await ProductModel.countDocuments(query);

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: req.user.id,
      targetId: req.user.id,
      targetType: "admin",
      details: { action: "viewed_products", query },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { products, total, page: Number(page), limit: Number(limit) },
    });
  } catch (error) {
    logger.error("List products error:", error);
    next(error);
  }
};

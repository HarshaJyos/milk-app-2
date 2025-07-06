import { Request, Response, NextFunction } from "express";
import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import speakeasy from "speakeasy";
import { v4 as uuidv4 } from "uuid";
import { redisClient } from "../config/redis";
import { config } from "../config";
import { logger } from "../utils/logger";
import {
  CustomerModel,
  VendorModel,
  AdminModel,
  AuditLogModel,
  NotificationModel,
} from "../models";
import { CustomerZodSchema, VendorZodSchema, AdminZodSchema } from "../models";
import {
  generateQRCode,
  encryptData,
  sendOTP,
  verifyOTP,
  uploadDocument,
} from "../utils/auth.utils";

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    role: "customer" | "vendor" | "admin" | "super_admin";
  };
}

// Customer Registration
export const customerRegister = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const parsed = CustomerZodSchema.parse(req.body);
    const existingCustomer = await CustomerModel.findOne({
      mobileNumber: parsed.mobileNumber,
    });
    if (existingCustomer) {
      res.status(StatusCodes.CONFLICT).json({
        success: false,
        error: "Mobile number already registered",
      });
      return;
    }

    const verificationSid = await sendOTP(parsed.mobileNumber);
    await redisClient.setEx(
      `otp:customer:${parsed.mobileNumber}`,
      5 * 60,
      verificationSid
    );

    const customer = new CustomerModel({
      ...parsed,
      schemaVersion: 1,
      metadata: {
        ...parsed.metadata,
        verificationStatus: "pending",
        verificationToken: uuidv4(),
      },
    });
    await customer.save();

    await AuditLogModel.create({
      action: "customer_updated",
      performedBy: customer._id,
      targetId: customer._id,
      targetType: "customer",
      details: { after: customer.toObject() },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { verificationToken: customer.metadata.verificationToken },
    });
  } catch (error) {
    logger.error("Customer registration error:", error);
    next(error);
  }
};

// Customer OTP Verification
export const customerVerifyOTP = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { mobileNumber, otp, verificationToken } = req.body;
    const customer = await CustomerModel.findOne({
      mobileNumber,
      "metadata.verificationToken": verificationToken,
    });
    if (!customer) {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Customer not found or invalid token",
      });
      return;
    }

    const isValidOTP = await verifyOTP(mobileNumber, otp);
    if (!isValidOTP) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Invalid or expired OTP",
      });
      return;
    }

    customer.metadata.verificationStatus = "verified";
    customer.status = "active";
    await customer.save();

    const token = jwt.sign(
      { id: customer._id.toString(), role: "customer" },
      config.jwt.secret as string,
      { expiresIn: config.jwt.expiresIn }
    );
    await redisClient.setEx(
      `session:customer:${customer._id}`,
      24 * 60 * 60,
      token
    );

    await AuditLogModel.create({
      action: "customer_updated",
      performedBy: customer._id,
      targetId: customer._id,
      targetType: "customer",
      details: { after: { verificationStatus: "verified" } },
      schemaVersion: 1,
    });

    await redisClient.del(`otp:customer:${mobileNumber}`);

    res.status(StatusCodes.OK).json({
      success: true,
      data: {
        jwt: token,
        customer: { _id: customer._id, name: customer.name, mobileNumber },
      },
    });
  } catch (error) {
    logger.error("Customer OTP verification error:", error);
    next(error);
  }
};

// Customer Login
export const customerLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { mobileNumber } = req.body;
    const customer = await CustomerModel.findOne({ mobileNumber });
    if (!customer || customer.status !== "active") {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Customer not found or inactive",
      });
      return;
    }

    const verificationSid = await sendOTP(mobileNumber);
    await redisClient.setEx(
      `otp:customer:${mobileNumber}`,
      5 * 60,
      verificationSid
    );

    await AuditLogModel.create({
      action: "customer_updated",
      performedBy: customer._id,
      targetId: customer._id,
      targetType: "customer",
      details: { action: "login_attempt" },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { verificationToken: customer.metadata.verificationToken },
    });
  } catch (error) {
    logger.error("Customer login error:", error);
    next(error);
  }
};

// Vendor Registration
export const vendorRegister = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const parsed = VendorZodSchema.parse(req.body);
    const files = req.files as Express.Multer.File[] | undefined;

    const existingVendor = await VendorModel.findOne({
      $or: [
        { mobileNumber: parsed.mobileNumber },
        { uniqueId: parsed.uniqueId },
      ],
    });
    if (existingVendor) {
      res.status(StatusCodes.CONFLICT).json({
        success: false,
        error: "Mobile number or unique ID already registered",
      });
      return;
    }

    const documents = files
      ? await Promise.all(
          files.map(async (file) => ({
            type: file.fieldname as "license" | "tax" | "identity",
            url: await uploadDocument(
              file.buffer,
              file.originalname,
              file.mimetype
            ),
            uploadedAt: new Date(),
          }))
        )
      : [];

    const qrCodeUrl = await generateQRCode(parsed.uniqueId);

    const vendor = new VendorModel({
      ...parsed,
      verification: { ...parsed.verification, documents },
      qrCode: { url: qrCodeUrl, generatedAt: new Date() },
      schemaVersion: 1,
    });
    vendor.shop.licenseNumber = parsed.shop.licenseNumber
      ? encryptData(parsed.shop.licenseNumber)
      : undefined;
    vendor.shop.taxId = parsed.shop.taxId
      ? encryptData(parsed.shop.taxId)
      : undefined;
    await vendor.save();

    const verificationSid = await sendOTP(parsed.mobileNumber);
    await redisClient.setEx(
      `otp:vendor:${parsed.mobileNumber}`,
      5 * 60,
      verificationSid
    );

    await NotificationModel.create({
      recipientId: vendor._id,
      recipientType: "vendor",
      type: "vendor_verification",
      message: {
        title: "Vendor Registration",
        body: "Your registration is pending admin approval.",
      },
      channel: ["email", "in_app"],
      status: "sent",
      priority: "high",
      schemaVersion: 1,
    });

    await AuditLogModel.create({
      action: "vendor_updated",
      performedBy: vendor._id,
      targetId: vendor._id,
      targetType: "vendor",
      details: { after: vendor.toObject() },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { verificationToken: vendor.metadata.verificationToken, qrCodeUrl },
    });
  } catch (error) {
    logger.error("Vendor registration error:", error);
    next(error);
  }
};

// Vendor OTP Verification
export const vendorVerifyOTP = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { mobileNumber, otp, verificationToken } = req.body;
    const vendor = await VendorModel.findOne({
      mobileNumber,
      "metadata.verificationToken": verificationToken,
    });
    if (!vendor) {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Vendor not found or invalid token",
      });
      return;
    }

    const isValidOTP = await verifyOTP(mobileNumber, otp);
    if (!isValidOTP) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Invalid or expired OTP",
      });
      return;
    }

    vendor.verification.status = "verified";
    await vendor.save();

    await NotificationModel.create({
      recipientId: vendor._id,
      recipientType: "vendor",
      type: "vendor_verification",
      message: {
        title: "Verification Successful",
        body: "Your account is verified, awaiting admin approval.",
      },
      channel: ["email", "in_app"],
      status: "sent",
      priority: "high",
      schemaVersion: 1,
    });

    await AuditLogModel.create({
      action: "vendor_updated",
      performedBy: vendor._id,
      targetId: vendor._id,
      targetType: "vendor",
      details: { after: { verificationStatus: "verified" } },
      schemaVersion: 1,
    });

    await redisClient.del(`otp:vendor:${mobileNumber}`);

    res.status(StatusCodes.OK).json({
      success: true,
      data: { message: "Vendor verified, awaiting admin approval" },
    });
  } catch (error) {
    logger.error("Vendor OTP verification error:", error);
    next(error);
  }
};

// Vendor Login
export const vendorLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { mobileNumber } = req.body;
    const vendor = await VendorModel.findOne({ mobileNumber });
    if (!vendor || vendor.status !== "approved") {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Vendor not found or not approved",
      });
      return;
    }

    const verificationSid = await sendOTP(mobileNumber);
    await redisClient.setEx(
      `otp:vendor:${mobileNumber}`,
      5 * 60,
      verificationSid
    );

    await AuditLogModel.create({
      action: "vendor_updated",
      performedBy: vendor._id,
      targetId: vendor._id,
      targetType: "vendor",
      details: { action: "login_attempt" },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { verificationToken: vendor.metadata.verificationToken },
    });
  } catch (error) {
    logger.error("Vendor login error:", error);
    next(error);
  }
};

// Admin Registration
export const adminRegister = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user || req.user.role !== "super_admin") {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Only super admins can register admins",
      });
      return;
    }

    const parsed = AdminZodSchema.parse(req.body);
    const existingAdmin = await AdminModel.findOne({ email: parsed.email });
    if (existingAdmin) {
      res.status(StatusCodes.CONFLICT).json({
        success: false,
        error: "Email already registered",
      });
      return;
    }

    const passwordHash = await bcrypt.hash(parsed.passwordHash, 10);
    const twoFactorSecret = parsed.twoFactor.enabled
      ? speakeasy.generateSecret({ length: 20 }).base32
      : undefined;

    const admin = new AdminModel({
      ...parsed,
      passwordHash,
      twoFactor: { ...parsed.twoFactor, secret: twoFactorSecret },
      schemaVersion: 1,
    });
    await admin.save();

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: req.user.id,
      targetId: admin._id,
      targetType: "admin",
      details: { after: admin.toObject() },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { admin: { _id: admin._id, email: admin.email, role: admin.role } },
    });
  } catch (error) {
    logger.error("Admin registration error:", error);
    next(error);
  }
};

// Admin Login
export const adminLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { email, password, twoFactorCode } = req.body;
    const admin = await AdminModel.findOne({ email });
    if (!admin || admin.status !== "active") {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Admin not found or inactive",
      });
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, admin.passwordHash);
    if (!isPasswordValid) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Invalid credentials",
      });
      return;
    }

    if (admin.twoFactor.enabled) {
      if (!twoFactorCode) {
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: "Two-factor code required",
        });
        return;
      }
      const isValid2FA = speakeasy.totp.verify({
        secret: admin.twoFactor.secret!,
        encoding: "base32",
        token: twoFactorCode,
      });
      if (!isValid2FA) {
        res.status(StatusCodes.UNAUTHORIZED).json({
          success: false,
          error: "Invalid two-factor code",
        });
        return;
      }
      admin.twoFactor.lastVerified = new Date();
    }

    const token = jwt.sign(
      { id: admin._id.toString(), role: admin.role },
      config.jwt.secret as string,
      { expiresIn: config.jwt.adminExpiresIn }
    );
    await redisClient.setEx(`session:admin:${admin._id}`, 8 * 60 * 60, token);

    admin.lastLogin = new Date();
    await admin.save();

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: admin._id,
      targetId: admin._id,
      targetType: "admin",
      details: { action: "login" },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: {
        jwt: token,
        admin: { _id: admin._id, email: admin.email, role: admin.role },
      },
    });
  } catch (error) {
    logger.error("Admin login error:", error);
    next(error);
  }
};

// Forgot Password (Admin Only)
export const forgotPassword = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { email } = req.body;
    const admin = await AdminModel.findOne({ email });
    if (!admin || admin.status !== "active") {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Admin not found",
      });
      return;
    }

    const resetToken = uuidv4();
    await redisClient.setEx(`reset:admin:${admin._id}`, 30 * 60, resetToken);

    await NotificationModel.create({
      recipientId: admin._id,
      recipientType: "admin",
      type: "password_reset",
      message: {
        title: "Password Reset Request",
        body: `Use this token to reset your password: ${resetToken}`,
      },
      channel: ["email"],
      status: "sent",
      priority: "high",
      schemaVersion: 1,
    });

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: admin._id,
      targetId: admin._id,
      targetType: "admin",
      details: { action: "forgot_password" },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { message: "Reset token sent to email" },
    });
  } catch (error) {
    logger.error("Forgot password error:", error);
    next(error);
  }
};

// Reset Password (Admin Only)
export const resetPassword = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { email, resetToken, newPassword } = req.body;
    const admin = await AdminModel.findOne({ email });
    if (!admin || admin.status !== "active") {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Admin not found",
      });
      return;
    }

    const storedToken = await redisClient.get(`reset:admin:${admin._id}`);
    if (storedToken !== resetToken) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Invalid or expired reset token",
      });
      return;
    }

    admin.passwordHash = await bcrypt.hash(newPassword, 10);
    await admin.save();

    await redisClient.del(`reset:admin:${admin._id}`);

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: admin._id,
      targetId: admin._id,
      targetType: "admin",
      details: { action: "password_reset" },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { message: "Password reset successfully" },
    });
  } catch (error) {
    logger.error("Reset password error:", error);
    next(error);
  }
};

// Logout
export const logout = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Not authenticated",
      });
      return;
    }

    await redisClient.del(`session:${req.user.role}:${req.user.id}`);

    await AuditLogModel.create({
      action: `${req.user.role}_updated`,
      performedBy: req.user.id,
      targetId: req.user.id,
      targetType: req.user.role,
      details: { action: "logout" },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { message: "Logged out successfully" },
    });
  } catch (error) {
    logger.error("Logout error:", error);
    next(error);
  }
};

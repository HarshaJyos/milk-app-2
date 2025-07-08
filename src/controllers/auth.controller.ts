//src/controllers/auth.controller.ts
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

    const verificationToken = uuidv4();
    const verificationSid = await sendOTP(parsed.mobileNumber);
    await redisClient.setEx(
      `otp:customer:${parsed.mobileNumber}`,
      5 * 60,
      verificationSid
    );

    const customerData = {
      ...parsed,
      schemaVersion: 1,
      metadata: {
        ...parsed.metadata,
        verificationStatus: "pending",
        verificationToken,
        source: parsed.metadata?.source || "web",
        i18n: parsed.metadata?.i18n || {
          timezone: "Asia/Kolkata",
          currency: "INR",
        },
        onboardingSource: parsed.metadata?.onboardingSource || "web",
        deviceId: parsed.metadata?.deviceId || null,
      },
      address: parsed.address || {
        street: "",
        city: "",
        state: "",
        postalCode: "",
        coordinates: parsed.coordinates
          ? {
              type: "Point",
              coordinates: [
                parsed.coordinates.longitude,
                parsed.coordinates.latitude,
              ],
            }
          : { type: "Point", coordinates: [0, 0] },
      },
      deliveryPreferences: parsed.deliveryPreferences || {
        timeSlot: "morning",
      },
      language: parsed.language || "en",
    };

    const customer = new CustomerModel(customerData);
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
      data: { verificationToken },
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
    // Parse stringified JSON fields if they exist
    const parsedBody = { ...req.body };
    if (typeof parsedBody.shop === "string") {
      try {
        parsedBody.shop = JSON.parse(parsedBody.shop);
      } catch (error) {
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: "Invalid JSON format for shop field",
        });
        return;
      }
    }
    if (typeof parsedBody.metadata === "string") {
      try {
        parsedBody.metadata = JSON.parse(parsedBody.metadata);
      } catch (error) {
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: "Invalid JSON format for metadata field",
        });
        return;
      }
    }
    const parsed = VendorZodSchema.parse(parsedBody);

    // Handle files from upload.fields
    const files = req.files as
      | { [fieldname: string]: Express.Multer.File[] }
      | undefined;
    const documents = files
      ? await Promise.all(
          Object.keys(files).flatMap((fieldname) =>
            files[fieldname].map(async (file) => ({
              type: fieldname as "license" | "tax" | "identity",
              url: await uploadDocument(
                file.buffer,
                file.originalname,
                file.mimetype
              ),
              uploadedAt: new Date(),
            }))
          )
        )
      : [];

    const existingVendor = await VendorModel.findOne({
      mobileNumber: parsed.mobileNumber,
    });
    if (existingVendor) {
      res.status(StatusCodes.CONFLICT).json({
        success: false,
        error: "Mobile number already registered",
      });
      return;
    }

    let uniqueId: string;
    let isUnique = false;
    do {
      uniqueId = uuidv4();
      const existingUniqueId = await VendorModel.findOne({ uniqueId });
      isUnique = !existingUniqueId;
    } while (!isUnique);

    const qrCodeUrl = await generateQRCode(uniqueId);

    const vendor = new VendorModel({
      ...parsed,
      uniqueId,
      qrCode: {
        url: qrCodeUrl,
        generatedAt: new Date(),
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      },
      verification: { ...parsed.verification, documents },
      schemaVersion: 1,
      metadata: {
        ...parsed.metadata,
        verificationToken: uuidv4(),
        onboardingSource: parsed.metadata?.onboardingSource || "self",
        rating: { average: 0, count: 0 },
        apiRateLimit: {
          limit: 1000,
          remaining: 1000,
          resetAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        },
      },
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

// Vendor OTP Login Verification
export const vendorVerifyLoginOTP = async (
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
    if (!vendor || vendor.status !== "approved") {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Vendor not found or not approved",
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

    const token = jwt.sign(
      { id: vendor._id.toString(), role: "vendor" },
      config.jwt.secret as string,
      { expiresIn: config.jwt.expiresIn }
    );
    await redisClient.setEx(
      `session:vendor:${vendor._id}`,
      24 * 60 * 60,
      token
    );

    vendor.lastLogin = new Date();
    await vendor.save();

    await AuditLogModel.create({
      action: "vendor_updated",
      performedBy: vendor._id,
      targetId: vendor._id,
      targetType: "vendor",
      details: { action: "login_success", lastLogin: vendor.lastLogin },
      schemaVersion: 1,
    });

    await redisClient.del(`otp:vendor:${mobileNumber}`);

    res.status(StatusCodes.OK).json({
      success: true,
      data: {
        jwt: token,
        vendor: {
          _id: vendor._id,
          name: vendor.name,
          mobileNumber,
          qrCodeUrl: vendor.qrCode?.url,
        },
      },
    });
  } catch (error) {
    logger.error("Vendor OTP login verification error:", error);
    next(error);
  }
};

// Admin Registration
export const adminRegister = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const parsed = AdminZodSchema.parse(req.body);

    const existingAdmin = await AdminModel.findOne({ email: parsed.email });
    if (existingAdmin) {
      res.status(StatusCodes.CONFLICT).json({
        success: false,
        error: "Email already registered",
      });
      return;
    }

    const passwordHash = await bcrypt.hash(parsed.password, 10);
    let twoFactorSecret: string | undefined;
    let twoFactorToken: string | undefined;

    if (parsed.twoFactor?.enabled) {
      const secretObj = speakeasy.generateSecret({ length: 20 });
      twoFactorSecret = secretObj.base32; // Generates ~32-character Base32 secret
      if (!/^[A-Z2-7]{16,32}$/.test(twoFactorSecret)) {
        throw new Error("Generated 2FA secret is not valid Base32");
      }
      twoFactorToken = uuidv4();
      await redisClient.setEx(
        `2fa:admin:${twoFactorToken}`,
        5 * 60,
        JSON.stringify({
          email: parsed.email,
          secret: twoFactorSecret,
        })
      );
    }

    const adminData = {
      ...parsed,
      passwordHash,
      twoFactor: {
        enabled: parsed.twoFactor?.enabled || false,
        secret: twoFactorSecret,
        lastVerified: null,
      },
      schemaVersion: 1,
    };

    const admin = new AdminModel(adminData);
    await admin.save();

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: admin._id,
      targetId: admin._id,
      targetType: "admin",
      details: { after: admin.toObject() },
      schemaVersion: 1,
    });

    const response: { success: boolean; data: any } = {
      success: true,
      data: { _id: admin._id, email: admin.email, role: admin.role },
    };

    if (parsed.twoFactor?.enabled) {
      response.data.twoFactorToken = twoFactorToken;
      response.data.message =
        "Two-factor authentication required to activate account";
      response.data.twoFactorSecret = twoFactorSecret; // Return secret for authenticator app setup
    }

    res.status(StatusCodes.OK).json(response);
  } catch (error) {
    logger.error("Admin registration error:", error);
    next(error);
  }
};

// Admin 2FA Verification
export const adminVerify2FA = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { email, twoFactorCode, twoFactorToken } = req.body;

    const twoFactorData = await redisClient.get(`2fa:admin:${twoFactorToken}`);
    if (!twoFactorData) {
      res.status(StatusCodes.BAD_REQUEST).json({
        success: false,
        error: "Invalid or expired 2FA token",
      });
      return;
    }

    const { email: storedEmail, secret } = JSON.parse(twoFactorData);
    if (storedEmail !== email) {
      res.status(StatusCodes.BAD_REQUEST).json({
        success: false,
        error: "Invalid email for 2FA token",
      });
      return;
    }

    if (!/^[A-Z2-7]{16,32}$/.test(secret)) {
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        error: "Invalid 2FA secret format",
      });
      return;
    }

    const isValid2FA = speakeasy.totp.verify({
      secret,
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

    const admin = await AdminModel.findOne({ email });
    if (!admin) {
      res.status(StatusCodes.NOT_FOUND).json({
        success: false,
        error: "Admin not found",
      });
      return;
    }

    admin.twoFactor.secret = secret;
    admin.twoFactor.lastVerified = new Date();
    admin.status = "active";
    await admin.save();

    const token = jwt.sign(
      { id: admin._id.toString(), role: admin.role as string },
      config.jwt.secret as string,
      { expiresIn: config.jwt.expiresIn }
    );
    if (admin.role === "super_admin") {
      await redisClient.setEx(
        `session:super_admin:${admin._id}`,
        24 * 60 * 60,
        token
      );
    } else if (admin.role === "support") {
      await redisClient.setEx(
        `session:support:${admin._id}`,
        24 * 60 * 60,
        token
      );
    } else if (admin.role === "finance") {
      await redisClient.setEx(
        `session:finance:${admin._id}`,
        24 * 60 * 60,
        token
      );
    } else if (admin.role === "operations") {
      await redisClient.setEx(
        `session:operations:${admin._id}`,
        24 * 60 * 60,
        token
      );
    }

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: admin._id,
      targetId: admin._id,
      targetType: "admin",
      details: { after: { twoFactor: admin.twoFactor, status: admin.status } },
      schemaVersion: 1,
    });

    await redisClient.del(`2fa:admin:${twoFactorToken}`);

    res.status(StatusCodes.OK).json({
      success: true,
      data: {
        jwt: token,
        admin: {
          _id: admin._id,
          email: admin.email,
          role: admin.role,
        },
      },
    });
  } catch (error) {
    logger.error("Admin 2FA verification error:", error);
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
    const { email, password } = req.body;

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
      if (!/^[A-Z2-7]{16,32}$/.test(admin.twoFactor.secret!)) {
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
          success: false,
          error: "Invalid 2FA secret format",
        });
        return;
      }

      const twoFactorToken = uuidv4();
      await redisClient.setEx(
        `2fa:admin:${twoFactorToken}`,
        5 * 60,
        JSON.stringify({
          email: admin.email,
          secret: admin.twoFactor.secret!,
        })
      );

      res.status(StatusCodes.OK).json({
        success: true,
        data: {
          twoFactorToken,
          message: "Two-factor authentication required",
        },
      });
      return;
    }

    const token = jwt.sign(
      { id: admin._id.toString(), role: admin.role as string },
      config.jwt.secret as string,
      { expiresIn: config.jwt.expiresIn }
    );
    if (admin.role === "super_admin") {
      await redisClient.setEx(
        `session:super_admin:${admin._id}`,
        24 * 60 * 60,
        token
      );
    } else if (admin.role === "support") {
      await redisClient.setEx(
        `session:support:${admin._id}`,
        24 * 60 * 60,
        token
      );
    } else if (admin.role === "finance") {
      await redisClient.setEx(
        `session:finance:${admin._id}`,
        24 * 60 * 60,
        token
      );
    } else if (admin.role === "operations") {
      await redisClient.setEx(
        `session:operations:${admin._id}`,
        24 * 60 * 60,
        token
      );
    }

    admin.lastLogin = new Date();
    await admin.save();

    await AuditLogModel.create({
      action: "admin_updated",
      performedBy: admin._id,
      targetId: admin._id,
      targetType: "admin",
      details: { action: "login_success", lastLogin: admin.lastLogin },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: {
        jwt: token,
        admin: {
          _id: admin._id,
          email: admin.email,
          role: admin.role,
        },
      },
    });
  } catch (error) {
    logger.error("Admin login error:", error);
    next(error);
  }
};

// Admin Toggle 2FA
export const adminToggle2FA = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const { enable, twoFactorCode } = req.body;
    if (typeof enable !== "boolean") {
      res.status(StatusCodes.BAD_REQUEST).json({
        success: false,
        error: "Enable must be a boolean",
      });
      return;
    }

    if (!req.user) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Unauthorized",
      });
      return;
    }

    const admin = await AdminModel.findById(req.user.id);
    if (!admin || admin.status !== "active") {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Admin not found or inactive",
      });
      return;
    }

    if (enable) {
      if (admin.twoFactor.enabled) {
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: "Two-factor authentication is already enabled",
        });
        return;
      }

      const secretObj = speakeasy.generateSecret({ length: 20 });
      const twoFactorSecret = secretObj.base32; // Generates ~32-character Base32 secret
      if (!/^[A-Z2-7]{16,32}$/.test(twoFactorSecret)) {
        throw new Error("Generated 2FA secret is not valid Base32");
      }
      const twoFactorToken = uuidv4();
      await redisClient.setEx(
        `2fa:admin:${twoFactorToken}`,
        5 * 60,
        JSON.stringify({
          email: admin.email,
          secret: twoFactorSecret,
        })
      );

      res.status(StatusCodes.OK).json({
        success: true,
        data: {
          twoFactorToken,
          twoFactorSecret, // Return secret for authenticator app setup
          message: "Verify two-factor code to enable 2FA",
        },
      });
      return;
    } else {
      if (!admin.twoFactor.enabled) {
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: "Two-factor authentication is already disabled",
        });
        return;
      }

      if (!twoFactorCode) {
        res.status(StatusCodes.BAD_REQUEST).json({
          success: false,
          error: "Two-factor code required to disable 2FA",
        });
        return;
      }

      if (!/^[A-Z2-7]{16,32}$/.test(admin.twoFactor.secret!)) {
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
          success: false,
          error: "Invalid 2FA secret format",
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

      admin.twoFactor.enabled = false;
      admin.twoFactor.secret = undefined;
      admin.twoFactor.lastVerified = undefined;
      await admin.save();

      await AuditLogModel.create({
        action: "admin_updated",
        performedBy: admin._id,
        targetId: admin._id,
        targetType: "admin",
        details: { after: { twoFactor: admin.twoFactor } },
        schemaVersion: 1,
      });

      res.status(StatusCodes.OK).json({
        success: true,
        data: { message: "Two-factor authentication disabled" },
      });
    }
  } catch (error) {
    logger.error("Admin 2FA toggle error:", error);
    next(error);
  }
};

// Logout (Customer, Vendor, Admin)
export const logout = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Unauthorized",
      });
      return;
    }

    const { id, role } = req.user;
    await redisClient.del(`session:${role}:${id}`);

    await AuditLogModel.create({
      action: `${role}_updated`,
      performedBy: id,
      targetId: id,
      targetType: role,
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

// Token Refresh
export const refreshToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Unauthorized",
      });
      return;
    }

    const { id, role } = req.user;
    let user;

    if (role === "customer") {
      user = await CustomerModel.findById(id);
    } else if (role === "vendor") {
      user = await VendorModel.findById(id);
    } else {
      user = await AdminModel.findById(id);
    }

    if (
      !user ||
      (role === "vendor" && user.status !== "approved") ||
      user.status !== "active"
    ) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "User not found or inactive",
      });
      return;
    }

    const newToken = jwt.sign(
      { id: user._id.toString(), role },
      config.jwt.secret as string,
      { expiresIn: config.jwt.expiresIn }
    );
    await redisClient.setEx(
      `session:${role}:${user._id}`,
      24 * 60 * 60,
      newToken
    );

    await AuditLogModel.create({
      action: `${role}_updated`,
      performedBy: user._id,
      targetId: user._id,
      targetType: role,
      details: { action: "token_refreshed" },
      schemaVersion: 1,
    });

    res.status(StatusCodes.OK).json({
      success: true,
      data: { jwt: newToken },
    });
  } catch (error) {
    logger.error("Token refresh error:", error);
    next(error);
  }
};

// Rate Limit Check Middleware (used internally)
export const checkRateLimit = async (
  key: string,
  limit: number,
  windowMs: number
): Promise<boolean> => {
  const count = await redisClient.incr(key);
  if (count === 1) {
    await redisClient.expire(key, windowMs / 1000);
  }
  return count <= limit;
};
